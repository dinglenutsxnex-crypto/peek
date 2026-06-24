# 백로그 분류표

이 문서는 2026-03-21 기준으로 열려 있는 GitHub 이슈 28개를 유지보수 재가동 관점에서 다시 묶은 결과다.  
상태 이름은 `docs/maintenance/issue-triage.md`의 공통 분류를 따른다.

## 요약

| 항목 | 수량 | 판단 |
| --- | --- | --- |
| 오픈 PR | 0 | 유지보수 기준선 PR `#728`은 이미 `master`에 병합되었다 |
| 오픈 이슈 | 28 | 표면상 28개지만, 실제 활성 작업 묶음은 대략 10개 안팎이고 일부는 `future-scope`로만 추적한다 |
| 즉시 닫기/대체 가능 후보 | 완료 | `#728`로 직접 커버된 이슈 8건은 병합 직후 정리했다 |
| 즉시 구현 후보 | 소수 | 릴리스 운영, storage 정책 마감, large-file / `.so` 재현 클러스터가 우선이다 |

## 최근 정리 완료

| 항목 | 처리 | 이유 |
| --- | --- | --- |
| PR `#728` | 병합 | 유지보수 기준선, SAF 전환, release/preview workflow, instrumentation merge gate, 여러 crash/UX 완화를 `master`에 반영 |
| PR `#729` | 병합 | incoming `ACTION_VIEW`/`EXTRA_STREAM` `content://` 경계와 외부 공유 project ZIP reopen 경계를 CI instrumentation으로 고정 |
| PR `#723`, `#724`, `#725`, `#726`, `#727` | 닫음 | `#728`에 흡수되었거나 현재 release/preview workflow로 대체됨 |
| PR `#704`, `#701`, `#699`, `#695`, `#693`, `#692`, `#677`, `#637`, `#615`, `#565` | 닫음 | 오래된 자동 bump/alpha 제안으로 현재 유지보수 기준선보다 뒤처짐 |
| 이슈 `#112` | 닫음 | SWF 요청은 `#721`로 통합 |
| 이슈 `#221` | 닫음 | 현재 유지보수 방향은 최신 Android 대응이며 Android 4.4 지원 복구는 범위 밖 |
| 이슈 `#280` | 닫음 | API 23에서 죽던 color picker dialog 경로는 현재 설정 화면에서 이미 제거되어 더 이상 활성 코드 경로가 아님 |
| 이슈 `#376`, `#490` | 닫음 | crash stack이 가리키던 예전 binary fragment/ViewPager2 UI는 현재 Compose 탭으로 대체되었고, 남아 있던 죽은 layout과 의존성도 제거함 |
| 이슈 `#438` | 닫음 | chooser 정렬이 empty label을 안전하게 처리하도록 이미 maintenance 브랜치에서 수정됨 |
| 이슈 `#672` | 닫음 | crash stack이 가리키던 `ProjectOverviewFragment` binding 경로는 현재 Compose 기반 overview 화면으로 대체되어 더 이상 활성 코드 경로가 아님 |
| 이슈 `#720`, `#670`, `#396`, `#348`, `#160`, `#159`, `#129`, `#123` | 닫음 | `#728`에 포함된 변경이 `master`에 병합되어 post-merge 정리 완료 |
| 이슈 `#95` | 닫음 | `#728`과 `#729`가 기본 SAF import/export/open 경로, incoming `content://` 공유 경계, project archive reopen 경계까지 `master`에 반영 |
| 이슈 `#162`, `#529`, `#706`, `#491` | reopen + `future-scope` | 지금 당장 하지는 않지만 나중에 다시 볼 수 있는 장기 기능 요청으로 분리 추적 |
| 이슈 `#717`, `#710`, `#582`, `#158` | reopen + `future-scope` | 현재 baseline 유지보수 범위는 아니지만 장기 검토 대상으로는 남겨둠 |

## 오픈 이슈 클러스터

| 작업 묶음 | 관련 이슈 | 제안 상태 | 판단 | 다음 액션 |
| --- | --- | --- | --- | --- |
| 대용량/메모리 크래시 | `#219`, `#235`, `#523` | `planned-fast-follow` | `#728`에서 큰 파일 byte cache 제한과 문자열 검색 결과 상한/stable key를 먼저 넣었고, `#741`에서 문자열 검색 입력 상한과 프로젝트 전환 시 탭/전역 캐시 리셋을 추가하고 있다 | 실제 150MB 파일과 긴 문자열 리스트로 재검증하고, 남아 있는 OOM 경로를 더 분리 |
| legacy RecyclerView crash | `#442` | `obsolete-or-policy-invalid` | stack trace가 가리키던 `fragment_string.xml`/`FoundStringAdapter` 경로는 이미 Compose UI로 대체되었고, 남아 있던 죽은 layout 리소스도 제거했다 | obsolete로 정리 |
| `.so`/ELF/autosetup | `#514`, `#543`, `#576`, `#137` | `planned-fast-follow` | `#728`에서 64-bit ELF machine type 매핑과 override autosetup 재적용 경로를 먼저 수정했다 | 실제 `.so` 샘플로 재검증하고 남는 parser 문제만 분리 |
| 구형 Android archive 감지 크래시 | `#507`, `#508` | `planned-fast-follow` | `#728`에서 archive 확장자 fast path와 `NoClassDefFoundError` 방어를 넣어 구형 Android의 Commons Compress 감지 크래시 경로를 우회했다 | Android 6~7 계열에서 archive chooser와 open 경로를 재확인하고 정리 |
| project-relative path assertion 크래시 | `#512` | `planned-fast-follow` | `#728`에서 drawer/tab 경로가 project 바깥 항목을 열려다 `getRelPath()` 예외로 죽지 않도록 null-safe guard를 넣었다 | stale project/drawer entry에서 실패 메시지로만 처리되는지 확인하고 정리 |
| crash report 저신호 묶음 | `#716` | `needs-repro` | 본문에 구체적인 stack trace가 없고 현재 정보만으로는 코드 경계를 특정하기 어렵다 | 최신 preview build 기준 재현 단계와 대상 파일을 다시 받아야 한다 |
| SWF 요청 | `#721` | `planned-fast-follow` | 모바일 SWF 확장/디컴파일 요구는 남아 있지만 추적 스레드는 하나로 줄었다 | 기준선 병합 후 포맷 확장 우선순위에서 다시 평가 |
| 포맷 확장 요청 | `#120`, `#116`, `#124` | `planned-fast-follow` | 기준선 복구 이후에 다시 잡는 편이 맞다 | 포맷별 난이도와 수요를 다시 평가 |
| 장기 기능 요청 | `#162`, `#529`, `#706`, `#491` | `future-scope` | 현재 유지보수 baseline을 넘지만 나중에 다시 볼 가치가 있는 기능 요청이다 | 열린 상태로 두고 `future-scope` 라벨로만 추적 |
| 장기 검토 기능 요청 | `#717`, `#710`, `#582`, `#158` | `future-scope` | 지금 유지보수 baseline 범위는 아니지만 future backlog로 남겨두기로 했다 | 열린 상태로 두고 `future-scope`로만 추적 |
| 모호한 기능 요청 | `#596`, `#532`, `#425` | `planned-fast-follow` | 일부는 수요가 있지만 설명이 짧고 구현 범위가 불명확하다 | export/search UX 개선 트랙으로 흡수할지 다시 판단 |
| 하이라이터 개선 | `#97` | `planned-fast-follow` | 품질 개선 항목으로는 타당하다 | 기준선 복구 후 UI/텍스트 렌더링 개선 트랙으로 이동 |

## 실제 우선순위

| 우선순위 | 항목 | 근거 |
| --- | --- | --- |
| 1 | large-file / `.so` 재현 클러스터 정리 | 오래된 crash report와 parser 관련 이슈를 실질 작업 묶음으로 줄일 수 있다 |
| 2 | 구형 Android archive / stale project 재확인 | 이미 완화한 경계를 실제 종료 가능한 상태로 정리해야 한다 |
| 3 | 포맷 확장 요청 재정렬 | 실제 유지보수 범위와 별도 연구 과제를 나눠야 한다 |
| 4 | power-user 기능 문서화 유지 | 기본 SAF 경로와 고급 권한 경로가 다시 섞이지 않도록 README와 설정 설명을 계속 일관되게 유지해야 한다 |

## 닫기 전 체크 규칙

| 상황 | 원칙 |
| --- | --- |
| 이미 `master`에 병합된 유지보수 기준선으로 커버된 이슈/PR | 병합 직후 닫고 관련 PR을 근거로 남긴다 |
| 오래된 dependabot PR | 그대로 병합하지 않고 새 업그레이드 작업으로 대체 |
| crash report | 재현 정보가 없으면 `needs-repro` 코멘트를 먼저 남긴다 |
| 기능 요청 | 유지보수 핵심 범위와 별도 제품 수준 요청을 분리한다 |
