#include <iostream>
#include <random>

// ver:3.14 macos

// sub_100051EE8
uint64_t string2int(const char *str) {
    uint64_t result = 0;
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    if (len == 0) {
        return 0;
    }
    for (ssize_t i = len - 1; i >= 0; --i) {
        char c = str[i];
        if (c == 'W') c = '0';
        if (c == 'X') c = 'O';
        if (c == 'Y') c = '1';
        if (c == 'Z') c = 'I';
        uint64_t val;
        if (c >= '0' && c <= '9') {
            val = c - '0';
        } else if (c >= 'A' && c <= 'Z') {
            // val = c - 'A' + 10;
            val = c - 55;
        } else {
            continue;
        }
        result = result * 32 + val;
    }
    return result;
}

std::string int2string(uint64_t value, size_t length) {
    std::string result;
    for (size_t i = 0; i < length; ++i) {
        uint64_t tmp = value % 32;
        value /= 32;
        if (tmp == 0) {
            result += 'W'; // 'W' will be converted to '0'
        } else if (tmp == 24) {
            result += 'X'; // 'X' → 'O'
        } else if (tmp == 1) {
            result += 'Y'; // 'Y' → '1'
        } else if (tmp == 18) {
            result += 'Z'; // 'Z' → 'I'
        } else if (tmp <= 9) {
            result += tmp + '0';
        } else {
            result += tmp + 55; // A=65 → 10+55
        }
    }
    return result;
}

// 100051DB8
uint32_t crc25(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t) data[i] << 24;
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ 0x04C11DB7;
            else
                crc <<= 1;
        }
    }
    return crc & 0x1FFFFFF;
}

// sub_100051B78
void verify(const std::string& key) {
    // std::string key = "ABCDE-ABCDE-ABCDE-ABCDE-ABCDE";
    // std::string key = "57J8Z-D2QD5-A37WU-LEG4E-43WYH";
    // std::string key = "QZ0RF-934M3-XU3YD-DPTFC-QS54X";
    std::string cleanKey;
    for (char c: key) {
        if (c != '-') cleanKey += c;
    }
    cleanKey[2] = cleanKey[0xE];
    auto part0Sign = string2int(cleanKey.substr(0x14, 5).c_str()); //偏移16-20,用于CRC校验
    auto part1Sign = string2int(cleanKey.substr(0xF, 5).c_str());
    auto part2Sign = string2int(cleanKey.substr(0x0, 7).c_str());
    auto part3Sign = string2int(cleanKey.substr(0x7, 7).c_str());

    uint32_t v9 = part0Sign ^ (part0Sign << 7);
    uint32_t v18 = v9 ^ part2Sign ^ 0x12345678;
    uint32_t n = v9 ^ part3Sign ^ 0x87654321;

    unsigned int keyMix[3] = {0};
    keyMix[0] = (part0Sign ^ (part0Sign << 7)) ^ part2Sign ^ 0x12345678;
    keyMix[1] = (part0Sign ^ (part0Sign << 7)) ^ part3Sign ^ 0x87654321;
    keyMix[2] = part1Sign;

    uint32_t crcSign = crc25((uint8_t *) keyMix, sizeof(keyMix));

    std::cout << "Key     : " << key << "\n";
    std::cout << "Cleaned : " << cleanKey << "\n";
    std::cout << "--- Parsed Parts ---\n";
    std::cout << "Part0Sign: 0x" << std::hex << part0Sign << "\n";
    std::cout << "Part1Sign: 0x" << std::hex << part1Sign << "\n";
    std::cout << "Part2Sign: 0x" << std::hex << part2Sign << "\n";
    std::cout << "Part3Sign: 0x" << std::hex << part3Sign << "\n";
    std::cout << "--- Validation ---\n";
    std::cout << "CRC Computed: 0x" << std::hex << crcSign << "\n";

    if (part0Sign == crcSign) {
        std::cout << "[+] Key is valid\n";
        // 从 v18 中解出信息位
        uint32_t field0 = v18 >> 21;
        uint32_t field1 = (v18 >> 16) & 0x1F;
        uint32_t field2 = (v18 >> 5) & 0x7FF;
        uint32_t field3 = v18 & 0x1F;

        // 从 n 中解出年月
        uint32_t year = n / 0xC0000 + 2000;
        uint32_t rawMonth = (n >> 16);
        uint32_t month = rawMonth - 3 * ((rawMonth / 3) & 0xFFFC);

        std::cout << "--- Decoded Fields ---\n";
        std::cout << "Field0 (Product ver)   : " << std::dec << field0 << "\n";
        std::cout << "Field1                 : " << field1 << "\n";
        std::cout << "Field2                 : " << field2 << "\n";
        std::cout << "Field3                 : " << field3 << "\n";
        std::cout << "--- Decoded Date ---\n";
        std::cout << "Year                   : " << year << "\n";
        std::cout << "Month                  : " << month << "\n";

    } else {
        std::cout << "[-] Incorrect key\n";
    }
}

std::string generate(int product = 2) {
    // https://github.com/Danz17/Proxifier-Keygen
    std::mt19937 rng((unsigned int) std::time(nullptr));
    const std::string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // 固定产品类型和过期时间
    // int product = 2; // 0=安装版，1=便携版，2=Mac版
    int expirationDate = 0; // 0=永不过期

    int base1 = 9600 + (rng() % (65536 - 9600)); // 相当于 0x2580 ~ 0xFFFF
    int base2 = rng() % 65536;

    int param1 = base1 + (product << 21); // product 存在 param1 的高位
    int param2 = base2 + (expirationDate << 16); // expirationDate 在 param2 的高位

    // 随机生成第四段（5位 Base32 字符）
    std::string fourthKeyPart;
    for (int i = 0; i < 5; ++i) {
        fourthKeyPart += charset[rng() % 36];
    }

    int param3 = (int) string2int(fourthKeyPart.c_str());

    // 拼装 keyMix 数据块
    uint8_t data[12];
    std::memcpy(data, &param1, 4);
    std::memcpy(data + 4, &param2, 4);
    std::memcpy(data + 8, &param3, 4);

    // 计算 CRC 校验值
    uint32_t value1 = crc25(data, sizeof(data));
    uint32_t value2 = value1 ^ (value1 << 7);
    uint32_t value3 = param1 ^ value2 ^ 0x12345678;
    uint32_t value4 = param2 ^ value2 ^ 0x87654321;

    // 编码为 Base32（带模糊字符替换）
    std::string part1 = int2string(value3, 7);
    std::string part2 = int2string(value4, 7);
    std::string part3 = part1.substr(2, 1); // 第15位 = 第3位
    std::string part4 = fourthKeyPart;
    std::string part5 = int2string(value1, 5);

    // 替换第3位字符，避免 'Y'
    char randChar = charset[rng() % 36];
    if (randChar == 'Y') randChar = 'Z';
    part1[2] = randChar;

    // 拼接 key 并加横杠
    std::string key = part1 + part2 + part3 + part4 + part5;
    key.insert(20, "-");
    key.insert(15, "-");
    key.insert(10, "-");
    key.insert(5, "-");
    return key;
}


int main(int argc, char* argv[]) {
    const char* program = std::strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];


    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  " << program << " verify <key>\n";
        std::cout << "  " << program << " generate [product=0|1|2]\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "verify") {
        if (argc < 3) {
            std::cerr << "Please provide a key to verify.\n";
            return 1;
        }
        std::string key = argv[2];
        verify(key);
    } else if (mode == "generate") {
        int product = 2;
        if (argc >= 3) product = std::stoi(argv[2]);
        std::string key = generate(product);
        std::cout << "Generated Key: " << key << " (Product: " << product << ")\n";
    } else {
        std::cerr << "Unknown command: " << mode << "\n";
        return 1;
    }

    return 0;
}
