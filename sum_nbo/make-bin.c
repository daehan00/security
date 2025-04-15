#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>  // for htonl()

void write_bin_file(const char* filename, uint32_t value) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        perror("파일 열기 실패");
        return;
    }

    uint32_t net_value = htonl(value);  // 호스트 → 네트워크 바이트 오더
    fwrite(&net_value, sizeof(uint32_t), 1, fp);

    fclose(fp);
    printf("%s 파일에 %u(0x%08X) 저장 완료\n", filename, value, value);
}

void write_invalid_2byte_file(const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        perror("2바이트 파일 열기 실패");
        return;
    }

    uint8_t data[2] = {0x12, 0x34};  // 임의 값 2바이트
    fwrite(data, sizeof(uint8_t), 2, fp);
    fclose(fp);
    printf("%s 파일에 2바이트 더미 데이터 저장 완료\n", filename);
}

void write_invalid_16byte_file(const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        perror("16바이트 파일 열기 실패");
        return;
    }

    uint8_t data[16] = {
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF, 0x00
    };
    fwrite(data, sizeof(uint8_t), 16, fp);
    fclose(fp);
    printf("%s 파일에 16바이트 더미 데이터 저장 완료\n", filename);
}

int main() {
    // 정상 테스트용
    write_bin_file("five-hundred.bin", 500);
    write_bin_file("thousand.bin", 1000);
    write_bin_file("30uk.bin", 3000000000);  // 30억
    write_bin_file("20uk.bin", 2000000000);  // 20억

    // 예외 테스트용
    write_invalid_2byte_file("invalid-2byte.bin");
    write_invalid_16byte_file("invalid-16byte.bin");

    return 0;
}
