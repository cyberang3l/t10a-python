#!/usr/bin/env python3

# Important points to keep in mind when communicating with the device:
#
# * Measurements at 500ms intervals. So there is no point reading faster than
#   that.
# * If only one receptor head, the head number must be set to "00"
# * When receiving a response we have to check that BCC is correct. Otherwise
#   repeat the command.

# BCC = Block Check Character - page 25

import sys
import time
from enum import IntEnum
from typing import NamedTuple
import serial


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


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

    # This is referred to as DATA 4 in the specification.
    # However, in this block we store the parameters of a request
    # or the status the response.
    STATUS_PARAM_OFFSET = CMD_OFFSET + CMD_BYTE_COUNT
    STATUS_PARAM_BYTE_COUNT = 4

    DATA_OFFSET = STATUS_PARAM_OFFSET + STATUS_PARAM_BYTE_COUNT
    DATA_BLOCK_BYTE_COUNT = 6
    DATA_BYTE_COUNT = 3 * DATA_BLOCK_BYTE_COUNT  # 3x6byte blocks
    DATA_BLOCK_3_OFFSET = DATA_OFFSET
    DATA_BLOCK_2_OFFSET = DATA_BLOCK_3_OFFSET + DATA_BLOCK_BYTE_COUNT
    DATA_BLOCK_1_OFFSET = DATA_BLOCK_2_OFFSET + DATA_BLOCK_BYTE_COUNT

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

    # pylint: disable=too-few-public-methods
    class GenericResponse(NamedTuple):
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

    class Data(NamedTuple):
        illuminance: int
        delta: int
        percent: int

    class DataResponse(NamedTuple):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        receptor_head: bytes
        command: IntEnum
        hold: IntEnum
        err: tuple
        range: IntEnum
        battery_level: IntEnum
        data: NamedTuple  # This should be a Data NamedTuple

    class ClearIntegratedDataResponse(NamedTuple):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        receptor_head: bytes
        command: IntEnum
        err: tuple

    class HOLD(IntEnum):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        RUN = 0
        HOLD = 1

    class CCF(IntEnum):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        DISABLED = 2
        ENABLED = 3

    class RANGE(IntEnum):
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

    class ERROR(IntEnum):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1: Reading the Measured Values
        """
        ERR_1 = 1
        ERR_2 = 2
        ERR_3 = 3
        ERR_4 = 5
        NORMAL_OPERATION_1 = 0x20  # (space character)
        NORMAL_OPERATION_2 = 7     # (space character)

    ERROR_DESC = {
        ERROR.ERR_1: ("Receptor head power is switched off. Switch off the"
                      " T-10A and then switch it back on"),
        ERROR.ERR_2: ("EEPROM error 1. Switch off the T-10A and the switch"
                      " it back on"),
        ERROR.ERR_3: ("EEPROM error 2. Switch off the T-10A and the switch"
                      " it back on"),
        ERROR.ERR_4: ("Measurement value over error. Measurement exceeds"
                      " the T-10A measurement range."),
        ERROR.NORMAL_OPERATION_1: "Normal Operation",
        ERROR.NORMAL_OPERATION_2: "Normal Operation",
    }

    class BATTERY_LEVEL(IntEnum):
        NORMAL = 0
        LOW = 1

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

        if (value == 99 or (value >= 0 and value <= 29)):
            self._rcp_head = value
            return

        raise ValueError(
            "receptor_head must be a numeric ID between 0 and 29")

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
                self.DATA_BLOCK_3_OFFSET:(
                    self.DATA_BLOCK_3_OFFSET+self.DATA_BLOCK_BYTE_COUNT)]
            data_block_2 = resp[
                self.DATA_BLOCK_2_OFFSET:(
                    self.DATA_BLOCK_2_OFFSET+self.DATA_BLOCK_BYTE_COUNT)]
            data_block_3 = resp[
                self.DATA_BLOCK_1_OFFSET:(
                    self.DATA_BLOCK_1_OFFSET+self.DATA_BLOCK_BYTE_COUNT)]
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

        return self.GenericResponse(
            receptor_head=receptor_head,
            command=self.CMD(int(cmd_response.decode('ascii'))),
            status=status,
            data=data)

    def _device_write(self, command, param, expect_response=True):
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
        if not expect_response:
            return None
        raw_response = self.serial.read(self._cmd_resp_length(command))
        resp = self._parse_response(raw_response, command)
        return resp

    def _parse_hold_from_status(self, status):
        HOLD_STATUS_BYTE_SHIFT = 0
        hold = status.decode('ascii')[HOLD_STATUS_BYTE_SHIFT]
        # Try to parse HOLD setting from status
        # HOLD can be returned with many different values

        class HOLD_STATUS(IntEnum):
            RUN_0 = 0
            HOLD_1 = 1
            RUN_2 = 2
            HOLD_3 = 3
            RUN_4 = 4
            HOLD_5 = 5
            RUN_6 = 6
            HOLD_7 = 7

        try:
            h = HOLD_STATUS(int(hold))
            if (h == HOLD_STATUS.HOLD_1 or
                    h == HOLD_STATUS.HOLD_3 or
                    h == HOLD_STATUS.HOLD_5 or
                    h == HOLD_STATUS.HOLD_7):
                return self.HOLD.HOLD
            return self.HOLD.RUN
        except ValueError as e:
            eprint("Could not parse HOLD status in response\n")
            raise e

    def _parse_err_from_status(self, status):
        ERROR_STATUS_BYTE_SHIFT = 1
        err = status.decode('ascii')[ERROR_STATUS_BYTE_SHIFT]
        # Try to parse the error from status
        # Note that one of the possible return values for
        # error is space (' '). This is a special value that
        # we need to convert back to a hex value
        if err == ' ':
            err = err.encode('ascii')[0]

        try:
            err_enum = self.ERROR(int(err))
            err = self.ERROR_DESC[err_enum]
            return tuple((err_enum, err))
        except ValueError as e:
            eprint("Could not parse ERROR in response\n")
            raise e

    def _parse_range_from_status(self, status):
        RANGE_STATUS_BYTE_SHIFT = 2
        rng = status.decode('ascii')[RANGE_STATUS_BYTE_SHIFT]
        # Try to parse the range from status
        try:
            return self.RANGE(int(rng))
        except ValueError as e:
            eprint("Could not parse RANGE in response\n")
            raise e

    def _parse_battery_level_from_status(self, status):
        BATTERY_LEVEL_STATUS_BYTE_SHIFT = 3
        battery_level = status.decode('ascii')[BATTERY_LEVEL_STATUS_BYTE_SHIFT]

        class BATTERY_LEVEL_STATUS(IntEnum):
            NORMAL_0 = 0
            LOW_1 = 1
            NORMAL_2 = 2
            LOW_3 = 3
        try:
            b = BATTERY_LEVEL_STATUS(int(battery_level))
            if (b == BATTERY_LEVEL_STATUS.NORMAL_0 or
                    b == BATTERY_LEVEL_STATUS.NORMAL_1):
                return self.BATTERY_LEVEL.NORMAL
            return self.BATTERY_LEVEL.LOW
        except ValueError as e:
            eprint("Could not parse BATTERY_LEVEL in response\n")
            raise e

    @staticmethod
    def _parse_data_block(datablock):
        decoded_data = datablock.decode('ascii')
        if decoded_data.strip() == '':
            return None

        sign = decoded_data[0]
        value = int(decoded_data[1:5])
        exp = int(decoded_data[5])

        def get_exp():
            exp_val = 0
            if exp == 0:
                exp_val = 10**-4
            elif exp == 1:
                exp_val = 10**-3
            elif exp == 2:
                exp_val = 10**-2
            elif exp == 3:
                exp_val = 10**-1
            elif exp == 4:
                exp_val = 10**0
            elif exp == 5:
                exp_val = 10**1
            elif exp == 6:
                exp_val = 10**2
            elif exp == 7:
                exp_val = 10**3
            elif exp == 8:
                exp_val = 10**4
            elif exp == 9:
                exp_val = 10**5
            return exp_val

        if sign == '-':
            return -value*get_exp()
        return value*get_exp()

    # pylint: disable-msg=too-many-arguments
    def _cmd_with_long_fmt_resp(self, cmd, hold, ccf, rng, silent):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 1: Foreword

        The commands explained in this manual are provided to request data, not
        measurements
        ...
        ...
        A wait time is required for range switching. Since the saved data will
        not be updated while the T-10 is switching the measuring range, the
        same data may be outputagain when a data request command is sent. In
        this case, a certain wait time must be provided between data request
        commands.

        # Interpreting the results:
        The reference used for Delta illuminance and percent is the reference
        illuminance set on the T-10A, and must be set beforehand. If no
        reference illuminance is set, the values for Delta illuminance and
        percent will be spaces. If we see only a 'space' value we return None
        by this function.
        """
        if not isinstance(hold, self.HOLD):
            raise ValueError(
                "Unknown HOLD value {}. Expected {} value type".format(
                    hold, self.HOLD))
        if not isinstance(ccf, self.CCF):
            raise ValueError(
                "Unknown CCF value {}. Expected {} value type".format(
                    ccf, self.CCF))
        if not isinstance(rng, self.RANGE):
            raise ValueError(
                "Unknown RANGE value {}. Expected {} value type".format(
                    rng, self.RANGE))

        def get_measurement_with_retries(
                cmd, params, requested_range, max_retries):
            resp = -1
            received_range = -1
            # If the received range is different than the range we requested
            # we need to get a new measurement. It takes up to half second
            # for a new measurement to be taken when changing range.
            count = 0
            while received_range != requested_range and count < max_retries:
                if count == max_retries:
                    raise BaseException(
                        "Reached max retries {}. Aborting.".format(
                            max_retries))

                if count != 0 and not silent:
                    eprint("Response range is different than the requested"
                           " one; range hasn't been updated yet.\n"
                           "Repeating command {}.".format(cmd))
                    time.sleep(0.6)
                resp = self._device_write(cmd, params)
                received_range = self._parse_range_from_status(resp.status)
                # If the requested range has been set to auto, return
                # immediately as the received_range will always be different
                # than the requested one.
                if requested_range == self.RANGE.AUTO:
                    return resp, received_range
                count += 1
            return resp, received_range

        params = (self._get_bytes_from_int_enum(hold) +
                  self._get_bytes_from_int_enum(ccf) +
                  self._get_bytes_from_int_enum(rng) +
                  b'0')

        resp, received_range = get_measurement_with_retries(
            cmd, params, rng, 10)

        data = self.Data(
            illuminance=self._parse_data_block(resp.data[0]),
            delta=self._parse_data_block(resp.data[1]),
            percent=self._parse_data_block(resp.data[2]))

        rmd_response = self.DataResponse(
            receptor_head=resp.receptor_head,
            command=resp.command,
            hold=self._parse_hold_from_status(resp.status),
            err=self._parse_err_from_status(resp.status),
            range=received_range,
            battery_level=self._parse_battery_level_from_status(resp.status),
            data=data)

        return rmd_response

    def read_measurement_data(self, hold, ccf, rng, silent=False):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.1
        """
        cmd = self.CMD.READ_MEASUREMENT_DATA
        return self._cmd_with_long_fmt_resp(cmd, hold, ccf, rng, silent)

    def read_integrated_data(self, hold, ccf, rng, silent=False):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.2
        """
        cmd = self.CMD.READ_INTEGRATED_DATA
        return self._cmd_with_long_fmt_resp(cmd, hold, ccf, rng, silent)

    def clear_integrated_data(self):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.3
        """
        cmd = self.CMD.CLEAR_INTEGRATED_DATA
        params = 4*self.SPACE
        resp = self._device_write(cmd, params)
        err = self._parse_err_from_status(resp.status)
        return self.ClearIntegratedDataResponse(
            receptor_head=resp.receptor_head,
            command=resp.command,
            err=err)

    def connect(self):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.4

        Connect must be the first command we send to the instrument before
        it accepts further commands. According to section 1 of the
        communication manual:

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

    def set_hold_status(self, hold):
        """
        https://www.konicaminolta.com.cn/instruments/download/manual/pdf/T-10-E.pdf
        Section 5.5
        """
        if self.receptor_head != b'99':
            raise ValueError(
                "SET_HOLD_STATUS require the receptor head value to be set"
                " 99. Current value {}".format(self.receptor_head))

        if not isinstance(hold, self.HOLD):
            raise ValueError(
                "Unknown HOLD value {}. Expected {} value type".format(
                    hold, self.HOLD))

        cmd = self.CMD.SET_HOLD_STATUS
        params = (self._get_bytes_from_int_enum(hold) +
                  self.SPACE + self.SPACE + b'0')
        self._device_write(cmd, params, False)
        # According to the manual we have to Wait at least 500ms after
        # receiving the command response before sending further commands.
        time.sleep(0.5)


def is_error(t10a_err):
    err, _ = t10a_err
    if (err == T10A.ERROR.NORMAL_OPERATION_1 or
            err == T10A.ERROR.NORMAL_OPERATION_2):
        return False
    return True


def pretty_measurement_print(resp):
    print("Receptor HEAD ID:", resp.receptor_head.decode())
    print("Response for command:", resp.command)
    print("Hold value:", resp.hold)
    print("Range value:", resp.range)
    print("Battery level:", resp.battery_level)
    print("Data:")
    print("  Illuminance:", resp.data.illuminance)
    print("  Delta:", resp.data.delta)
    print("  Percent:", resp.data.percent)
    if resp.battery_level == T10A.BATTERY_LEVEL.LOW:
        eprint("WARNING: Battery level is low. Please change the battery or"
               " plug the power cable.")
    if is_error(resp.err):
        _, err_msg = resp.err
        eprint("Error: ", err_msg)
    print()


def main():
    with T10A(port='/dev/ttyUSB0') as t10a:
        # Should always be the first command
        t10a.connect()

        # Read some measurment data from the default receptor
        # head with ID 0
        resp = t10a.read_measurement_data(
            T10A.HOLD.RUN,
            T10A.CCF.DISABLED,
            T10A.RANGE.RANGE_5)
        pretty_measurement_print(resp)

        # Read the integrated data
        resp = t10a.read_integrated_data(
            T10A.HOLD.RUN,
            T10A.CCF.DISABLED,
            T10A.RANGE.RANGE_5)
        pretty_measurement_print(resp)

        # Clear the integrated data. No response from this command
        resp = t10a.clear_integrated_data()
        if is_error(resp.err):
            print(resp)

        # The set_hold_status_command requires the receptor_head to be
        # set to 99 first.
        t10a.receptor_head = 99
        # Note the this command doesn't return a response.
        t10a.set_hold_status(T10A.HOLD.RUN)

        # Set the receptor_head back to 0 and read more measurements
        # from receptor 0
        t10a.receptor_head = 0
        resp = t10a.read_measurement_data(
            T10A.HOLD.RUN,
            T10A.CCF.DISABLED,
            T10A.RANGE.AUTO)
        pretty_measurement_print(resp)


if __name__ == "__main__":
    main()
