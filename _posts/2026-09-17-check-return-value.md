---
layout: single
title: '[Dreamhack] check-return-value: 디버거 분석: 함수 반환값(RAX) 및 메모리 포인터 추적 노트'
sidebar:
  nav: "main"
tag : [Reversing, System, Dreamhack, Ghidra, Assembly, x86-64, Debugging]
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
본 포스팅은 드림핵(Dreamhack) 리버스 엔지니어링 실습 문제 중 <b>Ghidra 디버거</b>를 활용한 분석 노트입니다. 디컴파일 의사코드 파싱부터, x86-64 호출 규약(Calling Convention)에 따른 RAX 반환값 레지스터 추적 및 메모리 포인터 역참조 원리를 중심으로 정리했습니다.
</div>

---

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/study.jpg' | relative_url }}" 
       alt="필기 노트" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[접근방법]</p>
</div>

# [Dreamhack] Ghidra 디버거를 활용한 반환값 및 메모리 추적 분석

## 1. 개요 및 핵심 분석 흐름

Ghidra 디버거를 통해 함수 호출 이후의 반환 상태를 추적하여 데이터 메모리 위치를 알아내는 분석 과정입니다.

* **핵심 분석 절차**:  
  1. 문자열 상수를 추적하여 메인 로직의 진입점 진입
  2. 디컴파일된 의사코드에서 주요 하위 함수(`FUN_0040152b`) 식별
  3. 함수 호출 직후 반환 지점(`ret`)에 중단점 설정 및 `Step Over` 실행
  4. x86-64 반환 레지스터(`RAX`)의 데이터(메모리 주소 포인터) 확인 및 메모리 뷰 참조

---

## 2. 주요 학습 및 분석 과정

### 1) 바이너리 로드 및 상위 함수 역추적

* **문자열 검색 (`Search` $\rightarrow$ `For Strings`)**:  
  바이너리 내에 포함된 `"OK, I will return flag."`와 같은 고유 문자열의 메모리 주소를 탐색합니다.
* **참조 역추적 (`Show References To Address`)**:  
  해당 문자열을 참조하는 주소를 우클릭하여 역추적함으로써, 해당 호출부가 상위 제어 로직(`main` 계열 함수) 내부임을 확인합니다.

---

### 2) Ghidra Decompiler 의사코드 로직 분석

```c
undefined8 FUN_004015b6(void)
{
  puts("OK, I will return flag.");
  FUN_0040152b(&DAT_00404080);  // 실제 핵심 처리 함수 호출
  puts("I have returned the flag :)");
  return 0;
}

```

* **`undefined8`**: Ghidra가 반환 타입을 정확히 추론하지 못했을 때 지정하는 **8바이트(64비트) 크기의 기본 데이터 타입**입니다.
* **`FUN_` / `DAT_**`: 심볼 이름(Symbol Name)이 제거된 바이너리에서 각각 함수 주소와 정적 데이터 주소를 뜻하는 Ghidra의 기본 명명 규칙입니다.
* **로직 추론**: `FUN_0040152b(&DAT_00404080)` 호출 과정에서 내부적으로 연산 및 데이터를 준비할 것으로 추정할 수 있습니다.

---

### 3) Step Over 실행 및 RAX 반환값 확인

1. **중단점 설정**: `FUN_0040152b` 함수 호출 직후(혹은 반환 위치)에 Breakpoint를 설정합니다.
2. **동적 실행 (`Step Over`)**: 함수 내부로 진입하지 않고 `Step Over`를 실행하여 해당 함수 연산을 한 번에 수행합니다.
3. **`RAX` 레지스터 참조**:
x86-64 호출 규약(System V AMD64 ABI / Windows x64)에 따라 함수의 반환값은 **`RAX` 레지스터**에 저장됩니다.

>  **분석 포인트**: `RAX`에 저장된 값(`0x407750`)은 데이터 값 자체가 아닌, 데이터가 저장되어 있는 **메모리 포인터 주소**입니다.

---

### 4) Memory 뷰를 통한 데이터 파싱

`RAX` 레지스터에 보관된 주소(`0x407750`)로 Ghidra의 **Memory 뷰** 창에서 이동(`Go to Address`)하여 해당 위치에 연속되어 있는 ASCII 바이트 배열 데이터를 파싱합니다.

---

## 3. 핵심 리버싱 용어 정리

| 키워드 | 설명 및 역할 |
| --- | --- |
| **Ghidra** | NSA에서 개발한 오픈소스 리버스 엔지니어링 툴 (디컴파일러 및 디버거 제공) |
| **Decompiler** | 바이너리 기계어/어셈블리를 C 언어 형태의 의사코드(Pseudocode)로 역변환하는 기능 |
| **undefined8** | 타입 추론이 안 된 8바이트(64비트) 변수/반환값을 나타내는 Ghidra 표기법 |
| **Show References** | 특정 데이터나 함수 주소를 호출하는 상위 참조 지점을 역추적하는 기능 |
| **RAX 레지스터** | x86-64 아키텍처에서 함수의 반환값(Return Value)을 보관하는 전용 레지스터 |

---

## 4. 핵심 정리 및 회고

1. **레지스터 역참조**: 함수 반환값이 직접적인 문자가 아닌 메모리 주소(Pointer)일 경우, `RAX` 레지스터가 가리키는 메모리 버퍼 영역을 한 번 더 조회해야 실제 데이터를 확인할 수 있습니다.
2. **동적 분석의 효율성**: 복잡한 내부 로직을 일일이 디컴파일하여 역산하지 않더라도, 함수 반환 직후의 레지스터 상태와 메모리를 관찰하면 정밀한 동분 분석이 가능합니다.
