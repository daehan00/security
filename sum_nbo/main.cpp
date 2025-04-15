#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>  // ntohl()

uint32_t readBinFile4Byte(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        perror("파일 열기 실패\n");
        exit(1);
    }

    uint32_t net_value; // 음수는 제대로 읽어올 수 없음(uint는 unsigned로 읽기 때문, 음수를 해결하려면 uint가 아니라 int를 사용해야 함.)
    int bytes_read = fread(&net_value, 1, sizeof(uint32_t), fp);

	// 파일 유효성 검사
    if (bytes_read < sizeof(uint32_t)) {
        fprintf(stderr, "파일 '%s': 4바이트 미만입니다.\n", filename);
        fclose(fp);
        exit(1);
    }

	int extra = fgetc(fp);
    if (extra != EOF) {
        fprintf(stderr, "파일 '%s': 4바이트 초과입니다.\n", filename);
        fclose(fp);
        exit(1);
    }

    fclose(fp);
    return ntohl(net_value);  // byte order 변경
}

int main(int argc, char* argv[]) {
    uint32_t sum = 0;
    for (int i = 1; i < argc; ++i) {
        uint32_t value = readBinFile4Byte(argv[i]);
        sum += value;

        printf("%u(0x%08x)", value, value); //uint이기 때문에 u로 출력
		// signed int는 음수를 표현하기 위해 2의 보수 방식을 사용하기 때문에 2^31-1(~21억) 만큼의 숫자만 표현 가능
        if (i + 1 == argc)
            printf(" = ");
        else
            printf(" + ");
    }

    printf("%u(0x%08x)\n", sum, sum);
    return 0;
}
