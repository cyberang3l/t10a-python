#!/usr/bin/env python3
from t10a import T10A, pretty_measurement_print, is_error


def main():
    with T10A(port='/dev/ttyUSB0') as t10a:
        # Should always be the first command
        t10a.connect()

        # Read some measurment data from the default receptor
        # head with ID 0. Force the range setting to range_5.
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

        # Clear the integrated data. This command only returns
        # potential errors.
        resp = t10a.clear_integrated_data()
        if is_error(resp.err):
            print(resp)

        # The set_hold_status_command requires the receptor_head to be
        # set to 99 first.
        t10a.receptor_head = 99
        # Note the this command doesn't return a response.
        t10a.set_hold_status(T10A.HOLD.RUN)

        # Set the receptor_head back to 0 and read more measurements
        # from receptor 0. Allow the instrument to pick the range
        # automatically.
        t10a.receptor_head = 0
        resp = t10a.read_measurement_data(
            T10A.HOLD.RUN,
            T10A.CCF.DISABLED,
            T10A.RANGE.AUTO)
        pretty_measurement_print(resp)


if __name__ == "__main__":
    main()
