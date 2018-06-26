#![no_std]

///
/// Basic implementation of a Simple Protocol client for [Elatec
/// TWN4](https://www.elatec-rfid.com/en/products/rfid-readerwriter-with-antenna/multi-frequency/twn4-multitech/)
/// family devices, based upon [embedded-hal](https://github.com/japaric/embedded-hal).

#[macro_use]
extern crate bitflags;
extern crate byteorder;
#[macro_use(block)]
extern crate nb;
extern crate embedded_hal as hal;

use commands::SimpleCmd;
use core::marker::PhantomData;
use core::time::Duration;
use hal::serial;

mod hex;

/// Run modes for the reader
pub mod mode {
    /// The reader is active and ready to take commands
    pub struct Run;
    /// The reader is in a low-power state and can be awoken by LPCD, incoming data, or timeout
    pub struct Sleep;
    /// (Unimplemented) The reader is stopped, and can be awoken by incoming data.
    pub struct Stop;
}

#[derive(Debug)]
/// Elatec Multitech3-based RFID card reader
pub struct Multitech3<RX, TX, MODE>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    /// RX serial pin
    rx: RX,
    /// TX serial pin
    tx: TX,
    #[doc(hidden)]
    _mode: PhantomData<MODE>,
}

/// Create a new instance of the reader accessed via the provided pins.
pub fn new<RX, TX>(rx: RX, tx: TX) -> Multitech3<RX, TX, mode::Run>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    Multitech3::<RX, TX, mode::Run> {
        rx,
        tx,
        _mode: PhantomData,
    }
}

impl<RX, TX, MODE> Multitech3<RX, TX, MODE>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    /// Execute a blocking read of a single byte from the serial port
    fn read_byte(&mut self) -> Result<u8, Error> {
        match block!(self.rx.read()) {
            Ok(c) => Ok(c),
            Err(_e) => Err(Error::Read),
        }
    }

    /// Execute a blocking read of a ASCII hex-encoded byte (i.e. two bytes) from the serial port
    fn read_hex_byte(&mut self) -> Result<u8, Error> {
        match hex::hex_byte_to_byte(self.read_byte()?, self.read_byte()?) {
            Ok(b) => Ok(b),
            Err(e) => Err(Error::Hex(e)),
        }
    }

    /// Read and return the status of the last operation
    fn read_err(&mut self) -> Result<ReaderError, Error> {
        Ok(ReaderError::from(self.read_hex_byte()?))
    }

    /// Read the status of the last operation and save the rest of the line in `buf`
    fn read_resp(&mut self, buf: &mut [u8]) -> Result<ReaderError, Error> {
        let err = self.read_err()?;
        match err {
            ReaderError::None(_) => {
                let mut i = 0;
                loop {
                    if i > buf.len() {
                        return Err(Error::BufferFull);
                    }

                    let c = match block!(self.rx.read()) {
                        Ok(c) => c,
                        Err(_e) => return Err(Error::Read),
                    };
                    if c == '\r' as u8 {
                        break;
                    }
                    buf[i] = c;
                    i += 1;
                }
                Ok(ReaderError::None(i))
            }
            _ => Err(Error::Reader(err)),
        }
    }
}

impl<RX, TX> Multitech3<RX, TX, mode::Sleep>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    /// Read the results of the sleep operation and return a running reader object
    pub fn into_running(
        mut self,
    ) -> Result<(Multitech3<RX, TX, mode::Run>, WakeReason), (Self, Error)> {
        let mut resp_buf = [0u8; 2];
        match self.read_resp(&mut resp_buf) {
            Ok(resp) => match resp {
                ReaderError::None(_) => {
                    let reason_code = match hex::hex_byte_to_byte(resp_buf[0], resp_buf[1]) {
                        Ok(c) => c,
                        Err(e) => return Err((self, Error::Hex(e))),
                    };

                    Ok((
                        Multitech3::<RX, TX, mode::Run> {
                            rx: self.rx,
                            tx: self.tx,
                            _mode: PhantomData,
                        },
                        WakeReason::from(reason_code),
                    ))
                }
                _ => Err((self, Error::Reader(resp))),
            },
            Err(e) => Err((self, e)),
        }
    }
}

impl<RX, TX> Multitech3<RX, TX, mode::Run>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    /// Write the commands to the serial port
    fn issue_cmd<C: SimpleCmd>(&mut self, buf: &mut [u8], cmd: &C) -> Result<(), Error> {
        let sz = cmd.get_cmd_hex(buf)?;
        self.write_buf(&buf[..sz])?;
        self.write_buf("\r".as_bytes())?;
        Ok(())
    }

    /// Write the entire contents of `buf` to the serial port
    fn write_buf(&mut self, buf: &[u8]) -> Result<(), Error> {
        for c in buf.iter() {
            match block!(self.tx.write(*c)) {
                Ok(_) => {}
                Err(_) => return Err(Error::Write),
            }
        }
        Ok(())
    }

    /// Reset the reader; does not return a status
    pub fn reset(&mut self) -> Result<(), Error> {
        let cmd = commands::Reset;
        self.issue_cmd(&mut [0u8; commands::Reset::CMD_LEN], &cmd)
    }

    /// Put the reader to sleep; will wake on low-power card detect or timeout
    pub fn sleep(mut self, dur: Duration) -> Result<Multitech3<RX, TX, mode::Sleep>, Error> {
        let sleep_cmd = commands::Sleep {
            period: dur,
            flags: commands::SleepFlags::WAKEUP_BY_TIMEOUT_MSK
                | commands::SleepFlags::WAKEUP_BY_LPCD_MSK,
        };
        match self.issue_cmd(&mut [0u8; commands::Sleep::CMD_LEN], &sleep_cmd) {
            Ok(_) => Ok(Multitech3::<RX, TX, mode::Sleep> {
                rx: self.rx,
                tx: self.tx,
                _mode: PhantomData,
            }),
            Err(e) => Err(e),
        }
    }

    /// Return the number of ticks the reader has been powered on
    pub fn get_sys_ticks(&mut self) -> Result<u32, Error> {
        const RESP_LEN: usize = 8;
        let mut resp_buf = [0u8; RESP_LEN];
        let cmd = commands::GetSysTicks;
        match self.issue_cmd(&mut [0u8; commands::GetSysTicks::CMD_LEN], &cmd) {
            Ok(_) => {
                let resp = self.read_resp(&mut resp_buf)?;
                match resp {
                    ReaderError::None(n) => cmd.parse_response(&mut resp_buf[..n]),
                    _ => Err(Error::Reader(resp)),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Return the reader version string in `buf`
    pub fn get_version_string(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let cmd = commands::GetVersionString {
            max_resp_len: core::cmp::min(0xFF as usize, buf.len()) as u16,
        };
        match self.issue_cmd(&mut [0u8; commands::GetVersionString::CMD_LEN], &cmd) {
            Ok(()) => {
                let resp = self.read_resp(buf)?;
                match resp {
                    ReaderError::None(n) => cmd.parse_response(&mut buf[..n]),
                    _ => Err(Error::Reader(resp)),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Execute a tag read operation and return the tag type and ID in `buf`
    ///
    /// This does no parsing of the tag information except to strip out TLV-esqe data sent during
    /// transmission. The data is returned in the form:
    /// ```
    /// [type: u8] [id_bit_cnt: u8] [tag_id: u8|...]
    /// ```
    pub fn search_tag(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        let cmd = commands::SearchTag;
        match self.issue_cmd(&mut [0u8; commands::SearchTag::CMD_LEN], &cmd) {
            Ok(()) => {
                // because the card data might include b"\r", we cannot use read_resp and must
                // instead read byte-by-byte, at which point we don't need to use parse_response,
                // since we can just unpack it directly as we read the bytes.

                let rdr_resp = ReaderError::from(self.read_hex_byte()?);
                match rdr_resp {
                    ReaderError::None(_) => {}
                    _ => return Err(Error::Reader(rdr_resp)),
                };

                let result = self.read_hex_byte()?;
                if result != 1u8 {
                    return Ok(None);
                }

                if buf.len() < 2 {
                    return Err(Error::BufferTooSmall(2));
                }

                buf[0] = self.read_hex_byte()?; // tag type
                let bit_count = self.read_hex_byte()?; // id bit count

                if bit_count == 0 {
                    return Ok(None);
                } else {
                    buf[1] = bit_count;
                }

                let id_bytes = self.read_hex_byte()? as usize;

                if buf.len() < id_bytes + 2 {
                    return Err(Error::BufferTooSmall(id_bytes + 2));
                }

                let mut i = 0;
                loop {
                    if i == id_bytes {
                        break;
                    }
                    buf[i + 2] = self.read_hex_byte()?;
                    i += 1;
                }

                Ok(Some(id_bytes + 2))
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
/// Exceptions occurring during reader operations
pub enum Error {
    /// The reader issued a response that could not be processed as expected
    BadResponse(usize),
    /// The provided buffer was filled but more data awaits
    BufferFull,
    /// The supplied buffer is too small - the inner value is the required size
    BufferTooSmall(usize),
    /// A read of the serial port failed
    ///
    /// TODO make this properly bubble up <RX as hal::serial::Read>::Error somehow
    Read,
    /// A write to the serial port failed
    Write,
    /// The reader is still asleep and no bytes were waiting
    StillAsleep,
    /// An unspecified error occurred
    Other,
    /// The requested function is unimplemented
    Unimplemented,
    /// Communication with the reader succeeded, but the reader returned an error
    Reader(ReaderError),
    /// An attempt to manipulate hex bytes failed
    Hex(hex::Error),
}

#[derive(Debug)]
/// Error responses returned by the reader
pub enum ReaderError {
    /// ERR_NONE; the inner value contains the number of subsequent bytes read
    None(usize),
    /// ERR_UNKNOWN_FUNCTION
    UnknownFunction,
    /// ERR_MISSING_PARAMETER
    MissingParameter,
    /// ERR_UNUSED_PARAMETERS
    UnusedParameters,
    /// ERR_INVALID_FUNCTION
    InvalidFunction,
    /// ERR_PARSER
    Parser,
    /// Unknown/unrecognized; the inner value contains the (hex-decoded) error value
    Unknown(u8),
}

impl From<u8> for ReaderError {
    /// Convert a hex-decoded byte response into a ReaderError
    fn from(code: u8) -> Self {
        match code {
            0 => ReaderError::None(0),
            1 => ReaderError::UnknownFunction,
            2 => ReaderError::MissingParameter,
            3 => ReaderError::UnusedParameters,
            4 => ReaderError::InvalidFunction,
            5 => ReaderError::Parser,
            _ => ReaderError::Unknown(code),
        }
    }
}

impl From<hex::Error> for Error {
    /// Turn a hex conversion error into an Error
    fn from(e: hex::Error) -> Self {
        Error::Hex(e)
    }
}

impl From<nb::Error<Error>> for Error {
    /// Convert an `nb::Error` into an Error
    fn from(e: nb::Error<Error>) -> Error {
        match e {
            nb::Error::Other(e) => e,
            _ => Error::Other,
        }
    }
}

#[derive(Debug)]
/// Reasons the reader has awoken from sleep
pub enum WakeReason {
    /// An unrecognized reason was returned during sleep
    Unknown,
    /// The USB input channel received at least one byte.
    USB,
    /// The input channel of COM1 received at least one byte.
    COM1,
    /// The input channel of COM2 received at least one byte.
    COM2,
    /// Sleep time ran out.
    Timeout,
    /// The presence of a transponder card was detected. (Supported by TWN4 MultiTech Nano only)
    LPCD,
}

impl From<u8> for WakeReason {
    /// Convert a hex-decoded sleep wake-up reason code into a WakeReason
    fn from(n: u8) -> Self {
        match n {
            1 => WakeReason::USB,
            2 => WakeReason::COM1,
            3 => WakeReason::COM2,
            4 => WakeReason::Timeout,
            5 => WakeReason::LPCD,
            _ => WakeReason::Unknown,
        }
    }
}

pub struct TagInfo<'i> {
    pub tag_type: u8,
    pub id_bit_count: u8,
    pub id: &'i [u8],
}

mod commands {
    use super::hex;
    use super::Error;
    use byteorder::{ByteOrder, LittleEndian};
    use core::time::Duration;

    fn copy_all_bytes(dest: &mut [u8], src: &[u8]) {
        dest[..src.len()].copy_from_slice(&src[..]);
    }

    fn check_bufsz(l: usize, b: &[u8]) -> Result<(), Error> {
        if b.len() < l {
            Err(Error::BufferTooSmall(l))
        } else {
            Ok(())
        }
    }

    /// Simple protocol commands
    pub trait SimpleCmd {
        /// The maximum length of a simple command in hex-encoded bytes
        const CMD_LEN: usize;
        /// The type of value returned in the parsed command response
        type Response;

        /// Retrieve hex-encoded command bytes to be sent to the reader into `buf`
        fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error>;
        /// Parse the hex-encoded response (excl. response code) in `buf`
        fn parse_response(&self, _buf: &mut [u8]) -> Result<Self::Response, Error> {
            Err(Error::Unimplemented)
        }
    }

    /// Reset the firmware (including any running App)
    pub struct Reset;

    impl SimpleCmd for Reset {
        const CMD_LEN: usize = 2;
        type Response = ();

        fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
            check_bufsz(Reset::CMD_LEN, buf)?;
            copy_all_bytes(buf, "0001".as_bytes());
            Ok(2)
        }
    }

    bitflags! {
        /// Sleep mode flags used in the sleep command
        pub struct SleepFlags: u32 {
            const WAKEUP_BY_USB_MSK = 0x1;
            const WAKEUP_BY_COM1_MSK = 0x2;
            const WAKEUP_BY_COM2_MSK = 0x4;
            const WAKEUP_BY_TIMEOUT_MSK = 0x10;
            const WAKEUP_BY_LPCD_MSK = 0x20;
            const SLEEPMODE_SLEEP = 0x0000;
            const SLEEPMODE_STOP = 0x0100;
        }
    }

    /// The device enters the sleep state for a specified time.
    ///
    /// During sleep state, the device reduces the current consumption to a value, which depends on the mode of sleep.
    pub struct Sleep {
        pub period: Duration,
        pub flags: SleepFlags,
    }

    impl SimpleCmd for Sleep {
        const CMD_LEN: usize = 20;
        type Response = ();

        fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
            check_bufsz(Sleep::CMD_LEN, buf)?;

            copy_all_bytes(buf, "0007".as_bytes());
            let mut u32_buf = [0u8; 4];
            LittleEndian::write_u32(
                &mut u32_buf,
                self.period.as_secs() as u32 * 1000 + self.period.subsec_millis(),
            );
            hex::bytes_to_hex(&u32_buf, &mut buf[4..12])?;
            LittleEndian::write_u32(&mut u32_buf, self.flags.bits());
            hex::bytes_to_hex(&u32_buf, &mut buf[12..20])?;
            Ok(Self::CMD_LEN)
        }
    }

    /// Retrieve number of system ticks, specified in multiple of 1 milliseconds, since startup of the firmware.
    pub struct GetSysTicks;

    impl SimpleCmd for GetSysTicks {
        const CMD_LEN: usize = 4;
        type Response = u32;

        fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
            check_bufsz(GetSysTicks::CMD_LEN, buf)?;

            copy_all_bytes(buf, "0003".as_bytes());
            Ok(GetSysTicks::CMD_LEN)
        }

        fn parse_response(&self, buf: &mut [u8]) -> Result<u32, Error> {
            if buf.len() != 8 {
                return Err(Error::BadResponse(buf.len()));
            }

            let mut result_buf = [0u8; 4];
            hex::hex_to_bytes(&buf, &mut result_buf)?;
            Ok(LittleEndian::read_u32(&result_buf))
        }
    }

    /// Retrieve version information.
    pub struct GetVersionString {
        pub max_resp_len: u16,
    }

    impl SimpleCmd for GetVersionString {
        const CMD_LEN: usize = 6;
        type Response = usize;

        fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
            check_bufsz(GetVersionString::CMD_LEN, buf)?;
            copy_all_bytes(buf, "0004".as_bytes());
            hex::bytes_to_hex(&[0xFFu8], &mut buf[4..])?;
            Ok(GetVersionString::CMD_LEN)
        }

        fn parse_response(&self, buf: &mut [u8]) -> Result<usize, Error> {
            const MAX_RESP_LEN: usize = 0xFF;
            let mut resp_len = [0u8];
            hex::hex_to_bytes(&[buf[0], buf[1]], &mut resp_len)?;
            let resp_len = resp_len[0] as usize;

            if resp_len * 2 != buf.len() - 2 || resp_len > MAX_RESP_LEN {
                return Err(Error::BadResponse(resp_len));
            }

            let mut resp_buf = [0u8; MAX_RESP_LEN];
            hex::hex_to_bytes(&buf[2..], &mut resp_buf)?;
            copy_all_bytes(buf, &resp_buf[..resp_len]);
            Ok(resp_len)
        }
    }

    /// Use this function to search a transponder in the reading range of TWN4.
    ///
    /// TWN4 is searching for all types of transponders, which have been specified via function
    /// SetTagTypes (unimplemented in this library). If a transponder has been found, tag type,
    /// length of ID and ID data itself are returned.
    pub struct SearchTag;

    impl SimpleCmd for SearchTag {
        const CMD_LEN: usize = 6;
        type Response = Option<usize>;

        fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
            check_bufsz(SearchTag::CMD_LEN, buf)?;
            copy_all_bytes(buf, "0500".as_bytes());
            hex::bytes_to_hex(&[0xFFu8], &mut buf[4..])?;
            Ok(SearchTag::CMD_LEN)
        }
    }
}
