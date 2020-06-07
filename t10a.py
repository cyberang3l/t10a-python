#!/usr/bin/env python3

# Important points to keep in mind when communicating with the device:
#
# * Measurements at 500ms intervals. So there is no point reading faster than
#   that.
# * If only one receptor head, the head number must be set to "00"
# * When receiving a response we have to check that BCC is correct. Otherwise
#   repeat the command.

# BCC = Block Check Character - page 25

from enum import IntEnum
from typing import NamedTuple
import serial


def insert_to_bytearray(barray, bytes_to_insert, offset):
    """
    Modifies the bytearray barray in place by adding the bytes_to_insert
    starting at the barray offset
    """
    for i, b in enumerate(bytes_to_insert):
        barray[offset+i] = b


class T10A(object):

    class COMM_FMT_RESP(IntEnum):
        # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        # Section 3.1 and 3.2 Short and Long Information Format
        SHORT_BYTE_COUNT = 14
        LONG_BYTE_COUNT = 32

    class CMD(IntEnum):
        # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        # Section 4: Command List
        READ_MEASUREMENT_DATA = 10
        READ_INTEGRATED_DATA = 11
        CLEAR_INTEGRATED_DATA = 28
        SET_PC_CONNECTION_MODE = 54
        SET_HOLD_STATUS = 55

    def _cmd_resp_length(self, cmd):
        if cmd == self.CMD.READ_MEASUREMENT_DATA:
            return int(self.COMM_FMT_RESP.LONG_BYTE_COUNT)
        elif cmd == self.CMD.READ_INTEGRATED_DATA:
            return int(self.COMM_FMT_RESP.LONG_BYTE_COUNT)
        elif cmd == self.CMD.CLEAR_INTEGRATED_DATA:
            return int(self.COMM_FMT_RESP.SHORT_BYTE_COUNT)
        elif cmd == self.CMD.SET_PC_CONNECTION_MODE:
            return int(self.COMM_FMT_RESP.SHORT_BYTE_COUNT)
        elif cmd == self.CMD.SET_HOLD_STATUS:
            return int(self.COMM_FMT_RESP.SHORT_BYTE_COUNT)
        raise ValueError("Unknown cmd " + cmd)

    @staticmethod
    def _get_bytes_from_int_enum(en):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 3.1 Short Information Format

        All the parameters except for STX (02H, ETX (03H), CR (0DH) and
        LF (0AH) must be specified by ASCII code.
        """
        return str(int(en)).encode('ascii')

    # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
    # Offsets for short/long format responses and values of STX, ETX and DELIM
    # are explained in Section 3: Protocol
    STX = bytes([0x02])
    STX_BYTE_COUNT = 1
    STX_OFFSET = 0

    RECEPTOR_HEAD_BYTE_COUNT = 2
    RECEPTOR_HEAD_OFFSET = STX_OFFSET + STX_BYTE_COUNT

    CMD_BYTE_COUNT = 2
    CMD_OFFSET = RECEPTOR_HEAD_OFFSET + RECEPTOR_HEAD_BYTE_COUNT

    STATUS_PARAM_OFFSET = CMD_OFFSET + CMD_BYTE_COUNT
    STATUS_PARAM_BYTE_COUNT = 4

    DATA_OFFSET = STATUS_PARAM_OFFSET + STATUS_PARAM_BYTE_COUNT
    DATA_BLOCK_BYTE_COUNT = 6
    DATA_BYTE_COUNT = 3 * DATA_BLOCK_BYTE_COUNT  # 3x6byte blocks
    DATA_BLOCK_1_OFFSET = DATA_OFFSET
    DATA_BLOCK_2_OFFSET = DATA_BLOCK_1_OFFSET + DATA_BLOCK_BYTE_COUNT
    DATA_BLOCK_3_OFFSET = DATA_BLOCK_2_OFFSET + DATA_BLOCK_BYTE_COUNT

    ETX = bytes([0x03])
    ETX_SHORT_OFFSET = STATUS_PARAM_OFFSET + STATUS_PARAM_BYTE_COUNT
    ETX_LONG_OFFSET = DATA_OFFSET + DATA_BYTE_COUNT

    BCC_BYTE_COUNT = 2
    BCC_SHORT_OFFSET = ETX_SHORT_OFFSET + 1
    BCC_LONG_OFFSET = ETX_LONG_OFFSET + 1

    DELIM = bytes([0x0D, 0x0A])  # [0Dh + 0Ah]
    DELIM_SHORT_OFFSET = BCC_SHORT_OFFSET + BCC_BYTE_COUNT
    DELIM_LONG_OFFSET = BCC_LONG_OFFSET + BCC_BYTE_COUNT

    SPACE = bytes([0x20])

    class Response(NamedTuple):  # pylint: disable=too-few-public-methods
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 3: Protocol

        The short response will only container a recepter_head, command and
        status while the long response will contain also the data.
        """
        receptor_head: bytes
        command: bytes
        status: bytes
        data: list

    def __init__(self, port):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 2: Communication Specifications
        """
        self._rcp_head = 0
        self._ser = serial.Serial()
        self._ser.port = port
        self._ser.baudrate = 9600
        self._ser.bytesize = 7
        self._ser.parity = serial.PARITY_EVEN
        self._ser.stopbits = serial.STOPBITS_ONE
        self._ser.timeout = 1

    @property
    def port(self):
        return self._ser.name

    @property
    def serial(self):
        return self._ser

    @serial.deleter
    def serial(self):
        del self._ser

    @property
    def receptor_head(self):
        return str(self._rcp_head).rjust(
            self.RECEPTOR_HEAD_BYTE_COUNT, '0').encode('ascii')

    @receptor_head.setter
    def receptor_head(self, value):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 1: Foreword

        If multiple receptor heads are connected to T-10, care must be taken
        when setting the receptor no. Setting ‘99’ will allowyou to send a
        command to all the connected receptor heads at once. (However, only
        command 55, which does not requirea reply from the receptor heads,
        can be used.)

        Also in Section 3.1: Short Information Format
        Receptor head selection (0 to 29; and 99 for all receptor heads)
        """
        if not isinstance(value, int):
            raise ValueError(
                "receptor_head must be a numeric ID of the"
                " receptor head connected to T10A")

        if value != 99 or value < 0 or value > 29:
            raise ValueError(
                "receptor_head must be a numeric ID between 0 and 29")

        self._rcp_head = value

    @receptor_head.deleter
    def receptor_head(self):
        del self._rcp_head

    def __enter__(self):
        if not self.is_open():
            self.open()
        return self

    def __exit__(self, *args, **kwargs):
        if self.is_open():
            self.close()

    def is_open(self):
        return self.serial.is_open

    def open(self):
        self.serial.open()

    def close(self):
        self.serial.close()

    @staticmethod
    def bcc_calc(barray):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 3.3
        """
        if not barray:
            raise ValueError("the bytearray cannot be empty")
        elif len(barray) == 1:
            return barray[0]
        bcc = barray[0]
        for i in range(len(barray)-1):
            bcc ^= barray[i+1]
        return format(bcc, '02x').upper().encode('ascii')

    def _parse_response(self, resp, for_cmd):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 3: Protocol
        """
        resp_fmt = self._cmd_resp_length(for_cmd)
        calculated_bcc = -1
        bcc_offset = -1
        receptor_head = resp[
            self.RECEPTOR_HEAD_OFFSET:(self.RECEPTOR_HEAD_OFFSET +
                                       self.RECEPTOR_HEAD_BYTE_COUNT)]
        status = resp[
            self.STATUS_PARAM_OFFSET:(self.STATUS_PARAM_OFFSET +
                                      self.STATUS_PARAM_BYTE_COUNT)]
        data = []

        if resp_fmt == self.COMM_FMT_RESP.SHORT_BYTE_COUNT:
            # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
            # Section 3.1 Short Information Format
            #
            # STX:            1 byte
            # RCPT_HEAD_NUM:  2 bytes
            # CMD NAME:       2 bytes
            # PARAM/STATUS    4 bytes
            # ETX:            1 byte
            # BCC:            2 bytes
            # CR:             1 byte
            # LF:             1 byte
            #                14 bytes total
            #
            # BCC Calculation: XOR (exclusive OR) of the data up
            #                  to ETX (excluding STX).
            # bytes 1-9
            bcc_offset = self.BCC_SHORT_OFFSET
        elif resp_fmt == self.COMM_FMT_RESP.LONG_BYTE_COUNT:
            # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
            # Section 3.2 Long Information Format
            #
            # Same with short format with the addition of data bytes
            # STX:                1 byte
            # RCPT_HEAD_NUM:      2 bytes
            # CMD NAME:           2 bytes
            # PARAM/STATUS        4 bytes
            # DATA (6x3 blocks): 18 bytes
            # ETX:                1 byte
            # BCC:                2 bytes
            # CR:                 1 byte
            # LF:                 1 byte
            #                    32 bytes total
            #
            # BCC Calculation: XOR (exclusive OR) of the data up
            #                  to ETX (excluding STX).
            # bytes 1-27
            bcc_offset = self.BCC_LONG_OFFSET
            data_block_1 = resp[
                self.DATA_BLOCK_1_OFFSET:(
                    self.DATA_BLOCK_1_OFFSET+self.DATA_BLOCK_BYTE_COUNT)]
            data_block_2 = resp[
                self.DATA_BLOCK_2_OFFSET:(
                    self.DATA_BLOCK_2_OFFSET+self.DATA_BLOCK_BYTE_COUNT)]
            data_block_3 = resp[
                self.DATA_BLOCK_3_OFFSET:(
                    self.DATA_BLOCK_3_OFFSET+self.DATA_BLOCK_BYTE_COUNT)]
            data = [data_block_1, data_block_2, data_block_3]
        else:
            raise ValueError("Unknown response format " + resp_fmt)

        calculated_bcc = self.bcc_calc(
            resp[self.RECEPTOR_HEAD_OFFSET:bcc_offset])
        received_bcc = resp[bcc_offset:bcc_offset+self.BCC_BYTE_COUNT]
        # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        # Section 1: Foreword
        #
        # Information to be used for communication with T-10 contains a sum
        # check code (BCC) that checks the contents of theinformation. By
        # performing a sum check, reliability of the information can be
        # maintained.
        if calculated_bcc != received_bcc:
            raise ValueError(
                "BCC mismatch: received {} but calculated {}".format(
                    received_bcc, calculated_bcc))

        # Validate that we received a response for the expected command
        cmd_response = resp[self.CMD_OFFSET:(self.CMD_OFFSET +
                                             self.CMD_BYTE_COUNT)]
        if int(cmd_response) != int(for_cmd):
            raise ValueError(
                "Expecting response for {} command. Received for {}".format(
                    int(for_cmd), int(cmd_response)))

        return self.Response(receptor_head, cmd_response, status, data)

    def _device_write(self, command, param):
        """
        The _device_write function sends a command and waits until a response
        is received. The response is parsed and its BCC is validated. If
        something goes wrong with the validation, an exception will be raised.
        """
        # All the writes use the short format. The response
        # might vary depending on the command.
        #
        # Description of the short format:
        #
        # STX:            1 byte
        # RCPT_HEAD_NUM:  2 bytes
        # CMD NAME:       2 bytes
        # PARAM/STATUS    4 bytes
        # ETX:            1 byte
        # BCC:            2 bytes
        # CR:             1 byte
        # LF:             1 byte
        #                14 bytes total
        #
        # BCC Calculation: XOR (exclusive OR) of the data up
        #                  to ETX (excluding STX).
        # bytes 1-9
        cmd = bytearray(14)

        insert_to_bytearray(cmd, self.STX, self.STX_OFFSET)
        insert_to_bytearray(cmd, self.receptor_head, self.RECEPTOR_HEAD_OFFSET)
        insert_to_bytearray(cmd, self._get_bytes_from_int_enum(command),
                            self.CMD_OFFSET)
        insert_to_bytearray(cmd, param, self.STATUS_PARAM_OFFSET)
        insert_to_bytearray(cmd, self.ETX, self.ETX_SHORT_OFFSET)
        # All the commands are in short format
        #
        # https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        # Section 1: Foreword
        #
        # Information to be used for communication with T-10 contains a sum
        # check code (BCC) that checks the contents of theinformation. By
        # performing a sum check, reliability of the information can be
        # maintained.
        bcc = self.bcc_calc(
            cmd[self.RECEPTOR_HEAD_OFFSET:self.BCC_SHORT_OFFSET])
        insert_to_bytearray(cmd, bcc, self.BCC_SHORT_OFFSET)
        insert_to_bytearray(cmd, self.DELIM, self.DELIM_SHORT_OFFSET)
        self.serial.write(cmd)
        raw_response = self.serial.read(self._cmd_resp_length(command))
        resp = self._parse_response(raw_response, command)
        return resp

    def connect(self):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 1: Foreword

        Prior to start of data communication with T-10, send command 54 to
        switch the connection mode to PC connection mode.Unless PC connection
        mode is established, communication with T-10 will be impossible. When
        carrying out an operation,the corresponding command must also be sent
        in accordance with the specified procedure.
        """
        cmd = self.CMD.SET_PC_CONNECTION_MODE
        params = b'1' + 3*self.SPACE
        resp = self._device_write(cmd, params)
        return resp

    class RMD_HOLD(IntEnum):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        RUN = 0
        HOLD = 1

    class RMD_CCF(IntEnum):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        DISABLED = 2
        ENABLED = 3

    class RMD_RANGE(IntEnum):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        AUTO = 0
        RANGE_1 = 1
        RANGE_2 = 2
        RANGE_3 = 3
        RANGE_4 = 4
        RANGE_5 = 5

    def read_measurement_data(self, hold, ccf, rng):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 1: Foreword

        The commands explained in this manual are provided to request data, not
        measurements
        ...
        ...
        A wait time is required for range switching.Since the saved data will
        not be updated while the T-10 is switching the measuring range, the
        same data may be outputagain when a data request command is sent. In
        this case, a certain wait time must be provided between data request
        commands.
        """
        if not isinstance(hold, self.RMD_HOLD):
            raise ValueError("Unknown HOLD value " + hold)
        if not isinstance(ccf, self.RMD_CCF):
            raise ValueError("Unknown CCF value " + ccf)
        if not isinstance(rng, self.RMD_RANGE):
            raise ValueError("Unknown RANGE value " + rng)

        cmd = self.CMD.READ_MEASUREMENT_DATA
        params = (self._get_bytes_from_int_enum(hold) +
                  self._get_bytes_from_int_enum(ccf) +
                  self._get_bytes_from_int_enum(rng) +
                  b'0')
        resp = self._device_write(cmd, params)
        return resp


def main():
    with T10A(port='/dev/ttyUSB0') as t10a:
        t10a.connect()
        resp = t10a.read_measurement_data(
            T10A.RMD_HOLD.RUN,
            T10A.RMD_CCF.DISABLED,
            T10A.RMD_RANGE.RANGE_5)
        print(resp.data[0])


if __name__ == "__main__":
    main()
