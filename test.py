raw_data = bytes(
    b'G6\x81\x83\x00\x01\x00\x00\x00\x01\x00\x01\x0blinuxseason\x03com\x00\x00\x1c\x00\x01\xc0\x18\x00\x06\x00\x01'
    b'\x00\x00\x03\x84\x00=\x01a\x0cgtld-servers\x03net\x00\x05nstld\x0cverisign-grs\xc0\x18\\\xde#7\x00\x00\x07\x08'
    b'\x00\x00\x03\x84\x00\t:\x80\x00\x01Q\x80\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00 '
)
Question_count = 1

questions = [None] * int(Question_count)
last_j = 12
for i in range(int(Question_count)):
    # d = DnsQuery
    j = 0
    Name = ""
    for j in range(len(raw_data[last_j + 1:])):
        if raw_data[j + last_j + 1] == 0:
            break

        if raw_data[j + last_j + 1] < 21:
            Name = Name + "."
        else:
            print(raw_data[j + last_j + 1])
            Name = Name + chr(raw_data[j + last_j + 1])

    # Name = str(raw_data[last_j + 1:j + last_j + 1])
    last_j = j + last_j + 1
    dnsType = raw_data[last_j + 1]
    questionClass = raw_data[last_j + 2]
    last_j += 2
    questions[i] = Name


print(Name)
