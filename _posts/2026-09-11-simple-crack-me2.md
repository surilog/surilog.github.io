---
layout: single
title: '[Dreamhack] simple-crack-me2 역산 알고리즘 분석 및 C++ 디코더 구현'
sidebar:
    nav: "main"
tag : [Reversing, System, Assembly, x86-64, Dreamhack, XOR, ReversingCode]
categories: [System, CS]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---

<div class="notice--info">  
본 포스팅은 Dreamhack의 simple-crack-me2 워게임 문제를 분석한 기록입니다. 디컴파일 및 리버스 엔지니어링을 통해 암호화 루틴을 파악하고, 역산(Bottom-Up) 알고리즘을 설계하여 C++ 복호화 스크립트를 작성한 과정을 다룹니다. (드림핵 가이드라인을 준수하여 FLAG 직접 노출은 지양하고 핵심 연산 분석 위주로 정리했습니다.)
</div>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/simple_crack_me2/note1.jpg' | relative_url }}" 
       alt="필기 노트" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[손으로 직접 작성해 본 역산 필기 노트]</p>
</div>

# [Dreamhack] simple-crack-me2 문제 분석 및 디코딩 노트

## 1. 개요 및 분석 접근법

* **대상 문제**: `simple-crack-me2`
* **주요 분석 흐름**:
  1. IDA / Ghidra에서 성공/실패 관련 문자열(`"Your input is wrong x("`)의 참조(Cross Reference, Xref)를 추적하여 핵심 검증 루틴인 `FUN_00401390()` 탐색.
  2. 입력값의 길이가 32바이트 (`0x20`)인지 확인한 후, 내부 인코딩 함수들의 동적/정적 연산 패턴 파악.
  3. 인코딩 과정을 역순(Bottom-Up)으로 밟아나가는 C++ 디코더 스크립트 작성.

---

## 2. 세부 함수 분석 (Reverse Engineering)

### ① `FUN_004011b6()` : 문자열 길이 측정 함수

```c
long FUN_004011b6(char *input) {
    long len = 0;
    for (char *p = input; *p != '\0'; p++) {
        len += 1;
    }
    return len; // input의 순수 문자열 길이를 반환 (strlen 연산)
}

```

---

### ② `FUN_004011ef()` : 순환 키 기반 XOR 연산 함수

```c
void FUN_004011ef(char *input, char *key) {
    size_t key_len = FUN_004011b6(key); // 키의 실제 문자열 길이를 동적 계산
    for (int i = 0; i < 0x20; i++) {
        input[i] = input[i] ^ key[i % key_len]; // 키를 순환(Modulo)하며 XOR
    }
}

```

* **분석 핵심 포인트**:
`key` 메모리 영역 중간에 Null Byte(`\x00`)가 포함되어 있으면, `FUN_004011b6()`의 특성상 Null 문자 전까지의 유효 문자열 길이만 `key_len`으로 인식됩니다.

---

### ③ `FUN_00401263()` : 바이트 가산 함수 (Inc)

```c
void FUN_00401263(char *input, char param_2) {
    for (int i = 0; i < 0x20; i++) {
        input[i] = input[i] + param_2; // 각 바이트에 param_2 값을 덧셈
    }
}

```

---

### ④ `FUN_004012b0()` : 바이트 감산 함수 (Dec)

```c
void FUN_004012b0(char *input, char param_2) {
    for (int i = 0; i < 0x20; i++) {
        input[i] = input[i] - param_2; // 각 바이트에서 param_2 값을 뺄셈
    }
}

```

---

## 3. 검증 루틴 (`FUN_00401390`) 인코딩/디코딩 순서

사용자가 입력한 32바이트 데이터는 아래와 같은 순서로 암호화 연산 과정을 거칩니다.

### [인코딩 연산 순서 (Target Execution Flow)]

1. `FUN_004011ef(input, "\xde\xad\xbe\xef")` $\rightarrow$ 순환 XOR 연산
2. `FUN_00401263(input, 0x1f)` $\rightarrow$ $+31$ (`0x1f`) 덧셈
3. `FUN_004012b0(input, 0x5a)` $\rightarrow$ $-90$ (`0x5a`) 뺄셈
4. `FUN_004011ef(input, "\xef\xbe\xad\xde")` $\rightarrow$ 순환 XOR 연산
5. `FUN_004012b0(input, 0x4d)` $\rightarrow$ $-77$ (`0x4d`, ASCII 'M') 뺄셈
6. `FUN_00401263(input, 0xf3)` $\rightarrow$ $+(-13)$ (`0xf3` 2의 보수 표현) 덧셈
7. `FUN_004011ef(input, key_00402072)` $\rightarrow$ 순환 XOR 연산
8. `memcmp(input, PTR_DAT_00404050, 0x20)` 비교 $\rightarrow$ 최종 인코딩 결과가 정답 데이터와 완벽히 일치해야 함.

---

### [역산/디코딩 매핑 테이블 (Decoding Strategy)]

인코딩 과정을 역순(Bottom-Up)으로 구성하며, 각 연산의 반대 연산(Inverse Operation)을 적용합니다. (XOR 연산은 자기 자신이 역연산)

| 단계 | 인코딩 연산 | 디코딩 역연산 적용 |
| --- | --- | --- |
| **1단계** | `XOR` (`key_00402072`) | `XORWithParam2(encoded, "\x11\x33\x55\x77\x99\xbb\xdd")` |
| **2단계** | `Inc` (`0xf3` / $-13$) | `DecWithParam2(encoded, -13)` |
| **3단계** | `Dec` (`0x4d` / $+77$) | `IncWithParam2(encoded, 77)` |
| **4단계** | `XOR` (`"\xef\xbe\xad\xde"`) | `XORWithParam2(encoded, "\xef\xbe\xad\xde")` |
| **5단계** | `Dec` (`0x5a` / $+90$) | `IncWithParam2(encoded, 90)` |
| **6단계** | `Inc` (`0x1f` / $+31$) | `DecWithParam2(encoded, 31)` |
| **7단계** | `XOR` (`"\xde\xad\xbe\xef"`) | `XORWithParam2(encoded, "\xde\xad\xbe\xef")` |

>  **메모리 분석 팁**:
> `0x0040206e` 주소에 연속으로 저장된 데이터 `be ad de 00 11 33 55 77 99 bb dd 00` 중, 7번째 연산에 전달되는 주소는 `+4` 오프셋 지점인 `\x11\x33\x55\x77\x99\xbb\xdd` 입니다.
> `GetStrLen` 함수가 `\x00` 전까지의 유효 길이를 $7$로 측정하므로, 오직 해당 7바이트 키만 반복 순회하며 XOR 연산에 참여하게 됩니다.

---

## 4. 디코딩 C++ 소스 코드

```cpp
#include <stdio.h>
#include <string.h>

// 문자열 길이 계산 함수 (GetStrLen)
size_t GetStrLen(const char* input) {
    size_t local_18 = 0;
    const char* local_10;

    for (local_10 = input; *local_10 != '\0'; local_10 = local_10 + 1) {
        local_18 += 1;
    }
    return local_18;
}

// 반복 키 XOR 함수 (XOR)
void XORWithParam2(unsigned char* input, const char* param_2) {
    size_t sVar1 = GetStrLen(param_2);
    for (int local_14 = 0; local_14 < 0x20; local_14 = local_14 + 1) {
        input[local_14] = param_2[(unsigned long)(long)local_14 % sVar1] ^ input[local_14];
    }
}

// 각 바이트 덧셈 함수 (Inc)
void IncWithParam2(unsigned char* input, char param_2) {
    for (int local_c = 0; local_c < 0x20; local_c = local_c + 1) {
        input[local_c] = param_2 + input[local_c];
    }
}

// 각 바이트 뺄셈 함수 (Dec)
void DecWithParam2(unsigned char* input, char param_2) {
    for (int local_c = 0; local_c < 0x20; local_c = local_c + 1) {
        input[local_c] = input[local_c] - param_2;
    }
}

// 역순으로 복호화를 수행하는 Decode 함수
void Decode(unsigned char* encoded) {
    // 1. 마지막 XOR 역산 (0x0040206e + 4 오프셋 주소의 7바이트 키)
    XORWithParam2(encoded, "\x11\x33\x55\x77\x99\xbb\xdd");

    // 2. Inc(0xf3) 역산 -> Dec(-13)
    DecWithParam2(encoded, -13);

    // 3. Dec(0x4d) 역산 -> Inc(77) ('M' = 77)
    IncWithParam2(encoded, 77);

    // 4. XOR("\xef\xbe\xad\xde") 역산
    XORWithParam2(encoded, "\xef\xbe\xad\xde");

    // 5. Dec(0x5a) 역산 -> Inc(90)
    IncWithParam2(encoded, 90);

    // 6. Inc(0x1f) 역산 -> Dec(31)
    DecWithParam2(encoded, 31);

    // 7. 최초 XOR("\xde\xad\xbe\xef") 역산
    XORWithParam2(encoded, "\xde\xad\xbe\xef");
}

int main(void) {
    // memcmp에서 비교 대상이 되는 final target data 32bytes (예시 헥스 배열 대입)
    unsigned char target_data[32] = {
        // [디버거/IDA에서 추출한 32바이트 헥스 값 배열 대입 지점]
        0x00, /* ... 32바이트 데이터 ... */
    };

    Decode(target_data);

    printf("Decoding Result (FLAG): %s\n", target_data);
    return 0;
}

```