import DBModel
import sys


if __name__ == '__main__':
    device_id = sys.argv[1]
    print(device_id)
    report = DBModel.get_scan_report(device_id)
    print(report)