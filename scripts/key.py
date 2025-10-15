def check_key():
    key_value = 0x541C78
    rounds = 8
    x = ""
    for _ in range(rounds):
        expected = key_value & 0xFF
        x += chr(expected)
        key_value -= ((key_value & 0x19) | 0x102)
    return x

if __name__ == "__main__":
    print("KEY:", check_key())

