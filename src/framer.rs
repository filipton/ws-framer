use crate::{crypto::Base64Pad, RngProvider, WsFrame, WsFrameHeader};
use core::marker::PhantomData;
#[cfg(feature = "http")]
use httparse::Header;

/// Framer used to retrieve data (websocket frames and http responses)
pub struct WsRxFramer<'a> {
    /// Internal buffer
    buf: &'a mut [u8],

    /// Header for frame that is currently parsed
    current_header: Option<WsFrameHeader>,

    /// Offset in internal buffer (for writing responses from server)
    write_offset: usize,

    /// Calculated current frame packet end offset
    current_packet_end: usize,

    /// If old frame should be disposed from internal buffer in next call
    shift: bool,
}

impl<'a> WsRxFramer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,

            current_header: None,
            write_offset: 0,
            current_packet_end: 0,
            shift: false,
        }
    }

    #[cfg(feature = "http")]
    pub fn process_http_response<'b>(&'b mut self, n: usize) -> Option<u16> {
        self.write_offset += n;

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        let res = resp.parse(&self.buf[..self.write_offset]).ok()?;

        if res.is_complete() {
            let code = resp.code.clone();
            let mut offset = res.unwrap();
            for header in resp.headers {
                if header.name == "Content-Length" {
                    let content_length =
                        usize::from_str_radix(core::str::from_utf8(header.value).ok()?, 10).ok()?;

                    offset += content_length;
                }
            }

            unsafe {
                core::ptr::copy(
                    self.buf.as_ptr().offset(offset as isize),
                    self.buf.as_mut_ptr(),
                    self.write_offset - offset,
                );
            }

            self.write_offset -= offset;
            return code;
        }

        None
    }

    pub fn process_data<'b>(&'b mut self) -> Option<WsFrame<'b>> {
        if self.shift {
            // shift all data left (dispose parsed frame data)
            unsafe {
                core::ptr::copy(
                    self.buf.as_ptr().offset(self.current_packet_end as isize),
                    self.buf.as_mut_ptr(),
                    self.write_offset - self.current_packet_end,
                );
            }

            self.shift = false;
            self.write_offset -= self.current_packet_end;
            self.current_packet_end = 0;
        }

        if self.current_header.is_none() {
            let tmp_buf = self.buf[0..self.write_offset].as_mut();
            let fin = (tmp_buf.get(0)? & 0b10000000) >> 7;
            let rsv1 = (tmp_buf.get(0)? & 0b01000000) >> 6;
            let rsv2 = (tmp_buf.get(0)? & 0b00100000) >> 5;
            let rsv3 = (tmp_buf.get(0)? & 0b00010000) >> 4;
            let opcode = tmp_buf.get(0)? & 0b00001111;
            let mask = (tmp_buf.get(1)? & 0b10000000) >> 7;
            let mut payload_len = (tmp_buf.get(1)? & 0b01111111) as usize;

            let mut offset = 2;
            if payload_len == 126 {
                payload_len = u16::from_be_bytes(tmp_buf.get(2..4)?.try_into().unwrap()) as usize;
                offset += 2;
            } else if payload_len == 127 {
                payload_len = u64::from_be_bytes(tmp_buf.get(2..10)?.try_into().unwrap()) as usize;
                offset += 8;
            }

            let mut masking_key = [0; 4];
            if mask == 1 {
                masking_key.copy_from_slice(&tmp_buf.get(offset..offset + 4)?);
                offset += 4;
            }

            self.current_header = Some(WsFrameHeader {
                fin: fin == 1,
                rsv1: rsv1 == 1,
                rsv2: rsv2 == 1,
                rsv3: rsv3 == 1,
                opcode,
                mask: mask == 1,
                masking_key,
                payload_len,
                offset,
            });

            self.current_packet_end = offset + payload_len;
        }

        // if frame fully received
        if self.write_offset >= self.current_packet_end && self.current_header.is_some() {
            let header = self.current_header.take().unwrap();
            self.shift = true; // shift on next invocation of process_data

            return Some(WsFrame::from_data(
                &header,
                &mut self.buf[header.offset..header.offset + header.payload_len],
            ));
        }

        None
    }

    pub fn mut_buf<'b>(&'b mut self) -> &'b mut [u8] {
        self.buf[self.write_offset..].as_mut()
    }

    pub fn revolve_write_offset(&mut self, n: usize) {
        self.write_offset += n;
    }
}

/// Framer used to send data (websocket frames and http upgrade requests)
pub struct WsTxFramer<'a, RG: RngProvider> {
    /// Internal buffer
    buf: &'a mut [u8],

    /// Boolean indicating if frames sent should be masked
    mask: bool,

    /// Rng provider phantom data
    rng_provider: core::marker::PhantomData<RG>,
}

impl<'a, RG: RngProvider> WsTxFramer<'a, RG> {
    pub fn new(mask: bool, buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            mask,

            rng_provider: PhantomData,
        }
    }

    #[cfg(feature = "http")]
    pub fn generate_http_upgrade<'b>(
        &'b mut self,
        host: &str,
        path: &str,
        additional_headers: Option<&[Header]>,
    ) -> &'b [u8] {
        let mut ws_key = [0u8; 16];
        RG::random_buf(&mut ws_key);
        let mut ws_key_b64 = [0u8; crate::consts::WS_KEY_B64_LEN];
        Base64Pad::encode_slice(&ws_key, &mut ws_key_b64);

        self.buf[0..4].copy_from_slice(b"GET ");
        let mut offset = 4 + path.as_bytes().len();
        self.buf[4..offset].copy_from_slice(path.as_bytes());
        self.buf[offset..offset + 11].copy_from_slice(b" HTTP/1.1\r\n");
        offset += 11;

        let headers = [
            Header {
                name: "Host",
                value: host.as_bytes(),
            },
            Header {
                name: "Sec-WebSocket-Key",
                value: &ws_key_b64,
            },
        ];

        self.append_headers(&crate::consts::WS_DEFAULT_CONNECT_HEADERS, &mut offset);
        self.append_headers(&headers, &mut offset);
        if let Some(additional) = additional_headers {
            self.append_headers(&additional, &mut offset);
        }

        self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
        &self.buf[0..offset + 2]
    }

    #[cfg(feature = "http")]
    pub fn generate_http_response<'b>(
        &'b mut self,
        status_code: u16,
        status_text: &str,
        headers: &[Header],
    ) -> &'b [u8] {
        self.buf[..9].copy_from_slice(b"HTTP/1.1 ");
        let mut itoa = itoa::Buffer::new();
        let status_code = itoa.format(status_code);

        self.buf[9..9 + status_code.len()].copy_from_slice(status_code.as_bytes());
        let mut offset = 9 + status_code.len();
        self.buf[offset] = b' ';
        self.buf[offset + 1..offset + 1 + status_text.len()]
            .copy_from_slice(status_text.as_bytes());
        offset += 1 + status_text.len();
        self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
        offset += 2;

        self.append_headers(&headers, &mut offset);
        self.buf[offset..offset + 2].copy_from_slice(b"\r\n");
        &self.buf[0..offset + 2]
    }

    fn append_headers<'b>(&'b mut self, headers: &[Header], offset: &mut usize) {
        for header in headers {
            self.buf[*offset..*offset + header.name.len()].copy_from_slice(header.name.as_bytes());
            *offset += header.name.len();

            self.buf[*offset..*offset + 2].copy_from_slice(b": ");
            *offset += 2;

            self.buf[*offset..*offset + header.value.len()].copy_from_slice(header.value);
            *offset += header.value.len();

            self.buf[*offset..*offset + 2].copy_from_slice(b"\r\n");
            *offset += 2;
        }
    }

    pub fn generate_packet<'b>(&'b mut self, header: &WsFrameHeader, data: &[u8]) -> &'b [u8] {
        let first_byte = (header.fin as u8) << 7
            | (header.rsv1 as u8) << 6
            | (header.rsv2 as u8) << 5
            | (header.rsv3 as u8) << 4
            | header.opcode & 0x0F;
        self.buf[0] = first_byte;

        let mut offset = 1;
        match header.payload_len {
            0..=125 => {
                self.buf[offset] = (header.mask as u8) << 7 | header.payload_len as u8;
                offset += 1;
            }
            126..crate::consts::U16_MAX => {
                self.buf[offset] = (header.mask as u8) << 7 | 126;
                self.buf[offset + 1..offset + 1 + 2]
                    .copy_from_slice(&(header.payload_len as u16).to_be_bytes());

                offset += 3;
            }
            crate::consts::U16_MAX.. => {
                self.buf[offset] = (header.mask as u8) << 7 | 127;
                self.buf[offset + 1..offset + 1 + 8]
                    .copy_from_slice(&(header.payload_len as u64).to_be_bytes());

                offset += 9;
            }
        }

        if header.mask {
            self.buf[offset..offset + 4].copy_from_slice(&header.masking_key);
            offset += 4;

            for d in data
                .iter()
                .enumerate()
                .map(|(i, &x)| x ^ header.masking_key[i % 4])
            {
                self.buf[offset] = d;
                offset += 1;
            }
        } else {
            self.buf[offset..offset + data.len()].copy_from_slice(data);
            offset += data.len();
        }

        &self.buf[..offset]
    }

    fn append_packet_data<'b>(
        &'b mut self,
        header: &WsFrameHeader,
        data: &[u8],
        mut offset: usize,
    ) -> &'b [u8] {
        if header.mask {
            for d in data
                .iter()
                .enumerate()
                .map(|(i, &x)| x ^ header.masking_key[i % 4])
            {
                self.buf[offset] = d;
                offset += 1;
            }
        } else {
            self.buf[offset..offset + data.len()].copy_from_slice(data);
            offset += data.len();
        }

        &self.buf[..offset]
    }

    pub fn frame<'b>(&'b mut self, frame: WsFrame<'_>) -> &'b [u8] {
        let mut masking_key = [0; 4];
        if self.mask {
            RG::random_buf(&mut masking_key);
        }

        let (payload, size) = match frame {
            WsFrame::Text(data) => (data.as_bytes(), data.as_bytes().len()),
            WsFrame::Binary(data) => (data, data.len()),
            WsFrame::Close(code, reason) => (&code.to_be_bytes()[..], 2 + reason.as_bytes().len()),
            WsFrame::Ping(data) => (data, data.len()),
            WsFrame::Pong(data) => (data, data.len()),
            WsFrame::Unknown => todo!(),
        };

        let header = WsFrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: frame.opcode(),
            mask: self.mask,
            masking_key,
            payload_len: size,
            offset: 0,
        };

        let data = if let WsFrame::Close(_, reason) = frame {
            let data = self.generate_packet(&header, payload);
            let data_len = data.len();

            self.append_packet_data(&header, reason.as_bytes(), data_len)
        } else {
            self.generate_packet(&header, payload)
        };

        data
    }

    pub fn text<'b>(&'b mut self, data: &str) -> &'b [u8] {
        self.frame(WsFrame::Text(data))
    }

    pub fn binary<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Binary(data))
    }

    pub fn close<'b>(&'b mut self, code: u16, reason: &str) -> &'b [u8] {
        self.frame(WsFrame::Close(code, reason))
    }

    pub fn ping<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Ping(data))
    }

    pub fn pong<'b>(&'b mut self, data: &[u8]) -> &'b [u8] {
        self.frame(WsFrame::Pong(data))
    }
}
