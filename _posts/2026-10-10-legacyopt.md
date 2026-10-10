---
layout: single
title: '[Dreamhack] legacyopt 문제 풀이 및 파이썬 복호화 분석 노트'
sidebar:
  nav: "main"
tag : [Reversing, System, Dreamhack, C, Python, IDA, Decompile, Algorithm, Ghidra]
categories: [System, CS]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---


**[Notice]**본 포스팅은 리버스 엔지니어링 학습용 디컴파일 코드 분석 노트입니다. 드림핵 가이드라인에 맞춰 전체 정답 FLAG 값 및 완성형 자동 스크립트는 포함하지 않으며, 암호화 알고리즘의 원리 분석과 역산 수식 유도, 그리고 파이썬을 활용한 헤더 검증 방식을 중심으로 정돈했습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/legacyopt/note.png' | relative_url }}" 
       alt="손 노트" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[손 노트]</p>
</div>

## 1. 개요 및 분석 접근법

* **대상 문제**: `legacyopt`
* **주요 분석 흐름**:  
  1. 심볼(Symbol)이 제거되어 있으므로, ELF 바이너리의 엔트리 포인트(`_start`)부터 추적하여 `__libc_start_main`의 첫 번째 인자로 전달되는 실제 `main()` 함수(`FUN_0010138c`) 식별.
  2. `main()` 함수에서 사용자 입력을 받은 후 호출하는 핵심 암호화 함수(`FUN_00101209`)의 제어 흐름 분석.
  3. `switch`문과 `do-while` 루프가 결합된 **더프 디바이스(Duff's Device)** 연산 패턴 및 8바이트 단위 시프트 메커니즘 파악.
  4. 암호문 길이에 따른 시작 키 인덱스 역산 방정식을 유도하고, 복호화 알고리즘(Pseudocode) 설계.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/legacyopt/main.png' | relative_url }}" 
       alt="main경로" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[main 경로]</p>
</div>

---
## 2. 더프 디바이스(Duff's Device)와 루프 언롤링 패턴이란?

### 2.1 더프 디바이스(Duff's Device)의 개념

**더프 디바이스(Duff's Device)**는 1983년 톰 더프(Tom Duff)가 루카스필름(Lucasfilm)에서 애니메이션 데이터를 고속으로 복사하기 위해 개발한 C 언어 고유의 루프 최적화 테크닉입니다.

이 기법의 가장 큰 특징은 **`switch`문과 `do-while` 루프가 하나의 구문 안으로 교차(Interleaving)하여 결합**되어 있다는 점입니다. C 언어의 표준 사양상 `switch`의 `case` 라벨은 루프 내부를 포함한 문맥(Context) 안쪽 어디든 배치될 수 있다는 점을 절묘하게 이용한 코드 패턴입니다.

### 2.2 왜 이러한 최적화를 사용했는가? (Why?)

가장 직관적인 질문은 *"왜 단순히 `for`나 `while` 루프를 쓰지 않고 이렇게 복잡한 구조를 사용하는가?"* 입니다. 주요 목적은 크게 두 가지입니다.

#### ① 루프 제어 오버헤드(Loop Control Overhead)의 극적인 감소

단순 루프가 1000번 실행될 때, CPU는 본체 연산 외에도 매 회차마다 다음과 같은 **부수적인 루프 제어 명령어**를 반복 실행합니다:

* 인덱스 변수 증가/차감 (`i++` 또는 `i--`)
* 루프 종료 조건 비교 (`cmp` / `test`)
* 조건부 분기 점프 (`jne` / `jle` 등)

만약 루프 본문을 8번 연속으로 펼치는 **루프 언롤링(Loop Unrolling)**을 적용하면, 루프 제어 명령어의 실행 횟수가 **1/8로 대폭 감소**합니다. 이는 CPU의 분기 예측(Branch Prediction) 실패 확률을 줄이고 명령어 파이프라인(Pipeline) 흐름을 원활하게 만들어 실행 속도를 획기적으로 높여줍니다.

#### ② 자투리 데이터(Remainder) 처리의 세련된 단일화

루프 언롤링을 적용할 때 가장 큰 걸림돌은 **"전체 데이터 길이가 언롤링 단위(예: 8)의 배수가 아닐 때 남는 자투리 데이터를 어떻게 처리할 것인가?"** 입니다.

* **일반적인 방식**: 8개씩 처리하는 언롤링 루프를 먼저 돌린 후, 남은 자투리(예: 3개)를 처리하는 별도의 잔여 루프(Remnant Loop)를 코드 뒤쪽에 추가로 작성함. (코드 중복 발생)
* **Duff's Device 방식**:  
  * `switch (length % 8)` 연산을 통해, **첫 번째 루프 진입 시 자투리 개수만큼만 실행되도록 루프 중간의 `case` 라벨로 직접 다이렉트 점프**합니다.
  * 첫 회차에서 자투리 데이터 처리를 끝마친 후, 나머지 데이터는 naturally 8개씩 완전히 언롤링된 `do-while` 루프를 계속 수행합니다.
  * 결과적으로 **별도의 잔여 처리 루프 없이, 단 하나의 통합된 구문으로 모든 길이의 데이터를 최적으로 처리**할 수 있게 됩니다.

### 2.3 리버싱 관점에서의 시사점

Ghidra나 IDA 같은 디컴파일러가 더프 디바이스 패턴을 복원할 때, `switch`문의 점프 테이블 라벨이 `do-while` 루프 안으로 복잡하게 얽혀 들어간 형태로 디컴파일됩니다.

이 구조가 **"8바이트 루프 언롤링 + 자투리 진입점 점프"**라는 배경 원리를 이해하고 있으면, 디컴파일 코드가 기괴해 보여도 당황하지 않고 정확한 데이터 처리 순서와 오프셋을 역산할 수 있습니다.

## 3. main() 함수 디컴파일 분석

리눅스 ELF 바이너리는 실행 시 가장 먼저 `__libc_start_main`을 호출하며, 첫 번째 인자로 실제 `main` 함수의 주소를 넘겨줍니다.

```c
undefined8 FUN_0010138c(void)

{
  void *__ptr;
  size_t sVar1;
  long in_FS_OFFSET; 
  //스택 보호 카나비 값을 가져오기 위한 세그먼트 레지스터(FS)의 오프셋을 가리키는 변수 선언
  int i; //i = i
  char input [104]; //input = input
  long local_20; //local_20 =  s
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28); 
  // local_20 = in_FS_OFFSET + 40
  __ptr = malloc(100); 
  fgets(,100,stdin);
  sVar1 = strcspn(input,"n");
  input[sVar1] = '0';
  sVar1 = strlen(input);
  FUN_00101209(__ptr,input,sVar1 & 0xffffffff); 
  //암호문 만듬, __ptr: 만들어진 암호문 공간,input(사용자 입력) , sVar1 & 0xffffffff ==> 입력 길이를 32비트로 다듬어 인자로 사용
  i = 0;
  while( true ) {
    sVar1 = strlen(input); 
    //루플 돌 때마다 input값의 길이를 다시 계산하여 sVar1에 저장
    if (sVar1 <= (ulong)(long)i) break; // 현재 카운터 (i) 가 input길이 이상이 되면 반복문 종류
    printf("%02hhx",(ulong)(uint)(int)*(char *)((long)__ptr + (long)i)); /
    /변환된 데이터 주소(__ptr + 1)에서 1바이트(char *)를 읽어, 소문자 2자리의 16진수 형식(%02hhx)로 출력.

    i = i + 1; // 카운터 변수를 1증가시켜 다음 바이트를 가리키도록 함.
  }
  free(__ptr); //while문 종료

  //힙 메모리 해제
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}


```

### 핵심 분석 요약

1. `fgets`로 입력받은 문자열에서 개행(`n`) 및 널 바이트(`0`)를 정돈합니다.
2. 입력 문자열의 32비트 길이(`sVar1 &amp; 0xffffffff`)를 인자로 `FUN_00101209` 함수에 넘겨 힙 공간(`__ptr`)에 암호문을 생성합니다.
3. 변환된 암호문을 1바이트씩 2자리 16진수(`%02hhx`) 형식으로 출력합니다.

---

## 4. 암호화 로직 분석 (`FUN_00101209`)

`FUN_00101209` 함수는 단순 루프가 아닌, C 언어의 **더프 디바이스(Duff's Device)** 기법을 활용한 루프 언롤링 최적화 패턴을 보여줍니다.

```c
void FUN_00101209(byte *__ptr,byte *input,int int(sVar1))
//param_1 = __ptr , param_2=input , param_3= sVar1 & 0xffffffff
{
  byte *local_28; // local_28 = v2
  byte *local_20; // local_20 = v1
  int i; // local_c = i
  

  //문자열 길이 param_3(sVar1)을 바탕으로 8바이트 씩 묶음을 몇 번 돌릴지 횟수(local_c)를 계산
  i = int(sVar1) + 7; // i = sVar1 +7
  if (int(sVar1) + 7 < 0) { // i + 7 < 0
    i = int(sVar1) + 0xe; // i = sVarl + 14
  }
  i = i >> 3; // >> 3 : 8로 나누는 나눗셈 연산 (예: 길이가 1에서 8 사이면 루프 횟수는 1이 됨)
  local_28 = input;
  local_20 = __ptr;
  switch(int(sVar1) % 8) { // 문자열 길이를 8로 나눈 나머지를 구하여, switch문으로 분기 이때 전체 문자열의 길이에 따라 시작점이 달라짐
  case 0:
    do { //do while 루프 시작
      *local_20 = *local_28 ^ 0x88; // local_20(v1==__ptr)에 local_28(v2==input)값 ^ 0x88 결과를 저장
      local_28 = local_28 + 1; // 포인터 1칸 씩 이동
      local_20 = local_20 + 1; //포인터 1칸 씩 이동
switchD_00101267_caseD_7: //나머지가 7일 때 goto로 점프해 들어오는 레이블
      *local_20 = *local_28 ^ 0x66; // local_20에 input과 ^0x66 연산 값 저장
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
switchD_00101267_caseD_6: 
      *local_20 = *local_28 ^ 0x44;
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
switchD_00101267_caseD_5:
      *local_20 = *local_28 ^ 0x11;
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
switchD_00101267_caseD_4:
      *local_20 = *local_28 ^ 0x77;
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
switchD_00101267_caseD_3:
      *local_20 = *local_28 ^ 0x55;
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
switchD_00101267_caseD_2:
      *local_20 = *local_28 ^ 0x22;
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
switchD_00101267_caseD_1:
      *local_20 = *local_28 ^ 0x33;
      i = i + -1; // 한 묶음(8글자) 처리가 완료될 지점=> 남은 루프 카운트를 1감소 시킴
      local_28 = local_28 + 1;
      local_20 = local_20 + 1;
    } while (0 < i); //아직 처리 해야 할 묶음이 있으면 다시 do 실행
    break;
  case 1:
    goto switchD_00101267_caseD_1;
  case 2:
    goto switchD_00101267_caseD_2;
  case 3:
    goto switchD_00101267_caseD_3;
  case 4:
    goto switchD_00101267_caseD_4;
  case 5:
    goto switchD_00101267_caseD_5;
  case 6:
    goto switchD_00101267_caseD_6;
  case 7:
    goto switchD_00101267_caseD_7;
  }
  return;
}

```

### 연산 구조 핵심 요약

* **루프 횟수 수식**: `i = (sVar1 + 7) &gt;&gt; 3`은 전체 문자열을 8바이트 묶음 단위로 나눈 총 반복 횟수를 계산합니다.
* **스위치 분기 특성**: 전체 문자열 길이의 나머지(`sVar1 % 8`)에 따라 첫 루프의 진입 지점이 달라집니다.
* **XOR 키 시퀀스**: `[0x88, 0x66, 0x44, 0x11, 0x77, 0x55, 0x22, 0x33]` 순서로 연산이 진행됩니다.  
  * 예: 나머지가 `0`이면 `0x88`부터 8개를 모두 거칩니다.
  * 예: 나머지가 `1`이면 `case 1`(`0x33`)로 점프하여 첫 바이트만 연산하고 카운터를 차감합니다.

---

## 5. 복호화 알고리즘 유도 및 의사코드 (Pseudocode)

### 시작 키 인덱스 역산 방정식

문자열 전체 길이(`L`)에 따라 암호화 시 처음으로 적용되는 XOR 키의 시작 오프셋이 달라집니다.

$$ text{start_index} = (8 - (L pmod 8)) pmod 8 $$

| 입력 길이 % 8 | 시작 레이블   | 첫 적용 키 | `start_index` 계산                 |
| --------- | -------- | ------ | -------------------------------- |
| **0**     | `case 0` | `0x88` | $(8 - 0) pmod 8 = mathbf{0}$ |
| **7**     | `case 7` | `0x66` | $(8 - 7) pmod 8 = mathbf{1}$ |
| **6**     | `case 6` | `0x44` | $(8 - 6) pmod 8 = mathbf{2}$ |
| **5**     | `case 5` | `0x11` | $(8 - 5) pmod 8 = mathbf{3}$ |
| **4**     | `case 4` | `0x77` | $(8 - 4) pmod 8 = mathbf{4}$ |
| **3**     | `case 3` | `0x55` | $(8 - 3) pmod 8 = mathbf{5}$ |
| **2**     | `case 2` | `0x22` | $(8 - 2) pmod 8 = mathbf{6}$ |
| **1**     | `case 1` | `0x33` | $(8 - 1) pmod 8 = mathbf{7}$ |

### 복호화 의사코드 (Python Concept)

드림핵 가이드라인에 따라 완제 스크립트 대신, 복호화 알고리즘의 핵심 구조를 나타낸 의사코드 스니펫입니다.

```py
# 복호화 알고리즘 핵심 개념 의사코드 (Pseudocode)

keys = [0x88, 0x66, 0x44, 0x11, 0x77, 0x55, 0x22, 0x33]


    # 암호문 길이에 따른 시작 키 인덱스 계산
    start_index = (8 - (length % 8)) % 8


    for byte in data_bytes:
        # XOR 연산의 대칭성을 이용하여 복호화
        decrypted_result.append(byte ^ key)

        # 다음 키 인덱스로 순환 순회 (+1 mod 8)
        current_key_idx = (current_key_idx + 1) % 8

    return decrypted_result

```

---

## 6. 핵심 정리 및 회고

1. **Duff's Device 루프 최적화**:  
  * 컴파일러가 반복문 수행 오버헤드를 줄이기 위해 `switch`문과 `do-while`을 조합하여 루프 언롤링을 적용한 형태를 확인했습니다.
  * 컴파일러 및 low-level C 프로그래밍에서 **루프 제어 오버헤드 감축**과 **자투리 데이터 처리의 단일화**를 위해 사용하는 클래식 최적화 패턴임을 확인했습니다.
2. **시작 오프셋 계산의 중요성**:  
  * 일반 순차 루프와 달리 **전체 데이터 길이의 나머지(`length % 8`)**에 따라 첫 번째 바이트에 적용되는 키 오프셋이 달라지므로, 이를 역산식 `(8 - (length % 8)) % 8`로 맞춰주는 것이 복호화의 핵심이었습니다.

3 **시작 오프셋 계산의 중요성**:  
* 일반 순차 루프와 달리 **전체 데이터 길이의 나머지(`length % 8`)**에 따라 첫 번째 바이트에 적용되는 키 오프셋이 달라지므로, 이를 역산식 `(8 - (length % 8))`로 정확히 구하는 것이 복호화의 핵심이었습니다.

4 **E-E-A-T 및 학습 시사점**:  
* 리버싱 중 난해해 보이는 디컴파일 코드를 만났을 때, 언어 고유의 컴파일러 최적화 패턴(Loop Unrolling, Duff's Device)을 이해하고 있으면 제어 흐름 분석 속도와 정확도를 비약적으로 높일 수 있음을 배운 문제였습니다.