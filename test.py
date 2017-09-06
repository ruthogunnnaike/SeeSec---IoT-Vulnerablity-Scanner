import sys


def validate_user_input(vulnerability_name, resolution_name):
    while True:
        consent = raw_input('Do you want SeeSec to resolve vulnerability: {0}, by {1} on your device? Enter Y(Yes) '
                            'or N(No)  \n'.format(vulnerability_name, resolution_name)).lower()
        if consent in ('y', 'yes', 'n', 'no'):
            if consent in ('y', 'yes'):
                print(resolution_name + '. Please wait.... \n')
                return 1
            elif consent in ('n', 'no'):
                while True:
                    confirm = raw_input('Are you sure you do not want to resolve vulnerability: {0}. Enter Y(Yes) to'
                                        ' cancel vulnerability fix, Enter N(No) to resolve vulnerability \n'.
                                        format(vulnerability_name)).lower()
                    if confirm in ('y', 'yes', 'n', 'no'):
                        if confirm in ('n', 'no'):
                            print(resolution_name + '. Please wait.... \n')
                            return 1
                        elif confirm in ('y', 'yes'):
                            print('You have opted out on resolving vulnerability: {0}. Please be aware your'
                                  ' device is vulnerable and you are at risk of a cyber attack. \n'
                                  .format(vulnerability_name))
                            return 0
                        else:
                            print('Onto the next...... \n')
                            return 0
                    else:
                        print('Enter a valid input \n')

            else:
                print('Discarding resolution on vulnerability: {0} \n'.format(vulnerability_name))
            break
        else:
            print('Enter a valid input')


def validate_user_input2(vulnerability_name, resolution_name):
    global returnVal

    while True:
        consent = raw_input('Do you want SeeSec to resolve vulnerability: {0}, by {1} on your device? Enter Y(Yes) '
                            'or N(No)  \n'.format(vulnerability_name, resolution_name)).lower()
        if consent in ('y', 'yes', 'n', 'no'):
            if consent in ('y', 'yes'):
                # print(resolution_name + '. Please wait.... \n')
                # print('print again')
                printSomething()
                returnVal = 1
                # return 1
            elif consent in ('n', 'no'):
                while True:
                    confirm = raw_input('Are you sure you do not want to resolve vulnerability: {0}. Enter Y(Yes) to'
                                        ' cancel vulnerability fix, Enter C(Cancel) to resolve vulnerability \n'.
                                        format(vulnerability_name)).lower()
                    if confirm in ('y', 'yes', 'c', 'cancel'):
                        if confirm in ('c', 'cancel'):
                            # print(resolution_name + '. Please wait.... \n')
                            returnVal = 1
                            # return 1
                        elif confirm in ('y', 'yes'):
                            print('You have opted out on resolving vulnerability: {0}. Please be aware your'
                                  ' device is vulnerable and you are at risk of a cyber attack. \n'
                                  .format(vulnerability_name))
                            print('print again')
                            returnVal=0
                            # return 0
                        else:
                            print('Onto the next...... \n')
                            returnVal = 0
                            # return 0
                    else:
                        print('Enter a valid input \n')

            else:
                print('Discarding resolution on vulnerability: {0} \n'.format(vulnerability_name))
            break
        else:
            print('Enter a valid input')

    return returnVal


def printSomething():
    print('printing something')


def resolve_ssh_scanner(vulnerability_name, resolution_name):
    user_consent = validate_user_input(vulnerability_name, resolution_name)
    return user_consent
    # if user_consent == 1:
    #     print('Run the resolution function')
    # else:
    #     print('Do nothing')


if __name__ == '__main__':
    device_id = sys.argv[1]
    mac_address = sys.argv[2]
    messages = ('Scan results for device: {0}, with MAC address: {1} \n \n'.format(device_id, mac_address)).upper()
    print(messages)
    print(resolve_ssh_scanner('Weak password', 'Updating password'))