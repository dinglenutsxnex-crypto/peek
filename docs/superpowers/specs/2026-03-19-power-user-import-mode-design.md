# Power-User Import Mode Design

## Summary

기본 파일 가져오기 흐름은 SAF를 기준으로 유지한다. 파워유저 기능은 별도 설정으로 명시적으로 활성화했을 때만 노출하고, 기본 사용자 경험과 구현 경로에서 분리한다.

## Goals

- 기본 사용자 경로는 Play 정책과 최신 Android 저장소 모델에 맞는 SAF 중심 흐름으로 유지한다.
- 루트 파일 탐색, 직접 경로 탐색, 앱 목록 기반 선택 등 파워유저 기능은 기본 경로와 분리한다.
- UI와 구현을 분리하기 위해 import entry point를 인터페이스로 추상화한다.

## Non-goals

- 이번 단계에서 루트 전용 구현을 새로 작성하지는 않는다.
- 모든 legacy power-user 기능을 복구하지는 않는다.
- 루트 권한 확보/검증 로직을 추가하지는 않는다.

## UX

### Standard mode

- 메인 화면에는 `Select file`만 보인다.
- 이 버튼은 바로 SAF `OpenDocument`를 호출한다.

### Power-user mode

- Settings에 `Enable power-user import options` 토글을 추가한다.
- 토글을 켜면 메인 화면에 `Advanced import` 버튼이 추가로 보인다.
- `Advanced import`는 기존 `NewFileChooserActivity`를 열고, 여기서만 non-SAF/advanced 소스를 노출한다.

## Architecture

### Import entry point boundary

- `ImportEntryPoint`:
  - `SafImport`
  - `AdvancedImport`
- `ImportEntryPointCatalog`:
  - power-user 설정값에 따라 화면에 노출할 entry point 목록을 결정한다.
- UI는 이 catalog만 보고 버튼을 렌더링한다.

### Settings boundary

- `PowerUserModeSettings`는 shared preference 접근을 캡슐화한다.
- UI는 직접 preference key 문자열을 알지 않는다.

### Advanced chooser boundary

- `NewFileChooserActivity`는 `EXTRA_POWER_USER_MODE`를 입력으로 받는다.
- power-user 모드일 때만 root/app/process/hash/zoo 등 advanced root items를 노출한다.

## Data flow

1. Settings에서 power-user toggle 변경
2. `PowerUserModeSettings`에 저장
3. `ProjectOverview`가 resume 시 설정값 재조회
4. `ImportEntryPointCatalog`가 visible entry points 계산
5. `Select file`은 SAF로 직접 import
6. `Advanced import`는 advanced chooser로 이동

## Testing

- `ImportEntryPointCatalogTest`
  - standard mode는 `SafImport`만 노출
  - power-user mode는 `SafImport`, `AdvancedImport`를 노출
- `PowerUserModeSettingsTest`는 이번 단계에서는 보류
- 기존 `testDebugUnitTest` 전체 회귀 확인

## Rollout

- 이번 PR에서는 토글 + 버튼 분리 + chooser gating만 도입한다.
- 후속 PR에서 root-only mode, direct-path mode, advanced source별 세부 제어를 추가한다.
