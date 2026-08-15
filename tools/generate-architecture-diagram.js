import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const OUTPUT = fileURLToPath(new URL("../docs/assets/clairveil-privacy-architecture.svg", import.meta.url));

const W = 2400;
const H = 1500;

const C = Object.freeze({
  bg: "#F7F9FC",
  panel: "#FFFFFF",
  ink: "#172033",
  muted: "#64748B",
  border: "#D8E1EE",
  blue: "#2563EB",
  blueDark: "#173B8E",
  blueFill: "#EEF5FF",
  purple: "#7C3AED",
  purpleFill: "#F6F0FF",
  green: "#07965A",
  greenFill: "#EAFBF3",
  orange: "#EA7A12",
  orangeFill: "#FFF5E8",
  red: "#E23A3A",
  redFill: "#FFF1F1",
  gray: "#6B7280",
  grayFill: "#F8FAFC",
  amber: "#A56A00",
  amberFill: "#FFF8E8"
});

const out = [];
const add = value => out.push(value);

const esc = value => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;");

function text(x, y, value, {
  size = 18,
  weight = 500,
  fill = C.ink,
  anchor = "middle"
} = {}) {
  const lines = Array.isArray(value) ? value : [value];
  const firstY = y - ((lines.length - 1) * size * 0.58);
  add(`<text x="${x}" y="${firstY}" text-anchor="${anchor}" font-family="Noto Sans KR, Apple SD Gothic Neo, sans-serif" font-size="${size}" font-weight="${weight}" fill="${fill}">`);
  lines.forEach((lineValue, index) => {
    add(`<tspan x="${x}" dy="${index === 0 ? 0 : size * 1.22}">${esc(lineValue)}</tspan>`);
  });
  add("</text>");
}

function rect(x, y, width, height, {
  fill = C.panel,
  stroke = C.border,
  strokeWidth = 2,
  radius = 20,
  dash = "",
  shadow = false
} = {}) {
  add(`<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}" stroke="${stroke}" stroke-width="${strokeWidth}"${dash ? ` stroke-dasharray="${dash}"` : ""}${shadow ? ' filter="url(#shadow)"' : ""}/>`);
}

function path(d, color, {
  width = 3,
  dash = "",
  arrow = true,
  startArrow = false
} = {}) {
  add(`<path d="${d}" fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round"${dash ? ` stroke-dasharray="${dash}"` : ""}${startArrow ? ` marker-start="url(#arrow-${color.slice(1)})"` : ""}${arrow ? ` marker-end="url(#arrow-${color.slice(1)})"` : ""}/>`);
}

function line(x1, y1, x2, y2, color, options = {}) {
  path(`M ${x1} ${y1} L ${x2} ${y2}`, color, options);
}

function tag(x, y, width, value, color, { lines = false } = {}) {
  const content = lines ? value : [value];
  const height = content.length > 1 ? 47 : 31;
  rect(x, y, width, height, { fill: C.panel, stroke: color, strokeWidth: 1.2, radius: 10 });
  text(x + width / 2, y + (content.length > 1 ? 19 : 20), content, {
    size: content.length > 1 ? 12 : 12.5,
    weight: 700,
    fill: color
  });
}

function bullet(x, y, value, color, { size = 15, weight = 500 } = {}) {
  add(`<circle cx="${x}" cy="${y - 5}" r="3.4" fill="${color}"/>`);
  text(x + 16, y, value, { size, weight, anchor: "start" });
}

function header(x, y, title, subtitle, color) {
  text(x, y, title, { size: 24, weight: 800, fill: color });
  if (subtitle) text(x, y + 32, subtitle, { size: 15, weight: 600, fill: C.muted });
}

function cubeIcon(x, y) {
  add(`<path d="M ${x} ${y - 22} l 22 -13 22 13 -22 13 Z" fill="#2563EB"/>`);
  add(`<path d="M ${x} ${y - 22} v 26 l 22 13 V ${y - 9} Z" fill="#1D4ED8"/>`);
  add(`<path d="M ${x + 44} ${y - 22} v 26 l -22 13 V ${y - 9} Z" fill="#60A5FA"/>`);
}

function userIcon(x, y) {
  add(`<circle cx="${x}" cy="${y - 15}" r="10" fill="${C.purple}"/>`);
  add(`<circle cx="${x}" cy="${y}" r="31" fill="none" stroke="${C.purple}" stroke-width="2.5"/>`);
  add(`<path d="M ${x - 23} ${y + 20} Q ${x} ${y - 2} ${x + 23} ${y + 20}" fill="none" stroke="${C.purple}" stroke-width="5" stroke-linecap="round"/>`);
  rect(x + 50, y - 25, 72, 54, { fill: C.panel, stroke: C.purple, strokeWidth: 2.5, radius: 10 });
  add(`<circle cx="${x + 107}" cy="${y + 2}" r="4" fill="${C.purple}"/>`);
}

function walletIcon(x, y) {
  rect(x - 48, y - 24, 94, 54, { fill: C.panel, stroke: C.purple, strokeWidth: 3, radius: 12 });
  rect(x + 10, y - 8, 49, 24, { fill: "#E9DEFF", stroke: C.purple, strokeWidth: 2, radius: 8 });
  add(`<circle cx="${x + 39}" cy="${y + 4}" r="4" fill="${C.purple}"/>`);
}

function databaseIcon(x, y) {
  add(`<ellipse cx="${x}" cy="${y}" rx="23" ry="9" fill="#D9E8FF" stroke="${C.blue}" stroke-width="2"/>`);
  add(`<path d="M ${x - 23} ${y} v 31 c 0 6 10 9 23 9 s 23 -3 23 -9 v -31" fill="${C.blueFill}" stroke="${C.blue}" stroke-width="2"/>`);
  add(`<ellipse cx="${x}" cy="${y + 31}" rx="23" ry="9" fill="${C.blueFill}" stroke="${C.blue}" stroke-width="2"/>`);
}

function proverIcon(x, y) {
  add(`<path d="M ${x} ${y - 24} l 21 12 v 24 l -21 12 -21 -12 v -24 Z" fill="#BDF1D8" stroke="${C.green}" stroke-width="2.5"/>`);
  add(`<circle cx="${x}" cy="${y}" r="8" fill="${C.green}"/>`);
}

function serverIcon(x, y) {
  for (let index = 0; index < 3; index += 1) {
    rect(x, y + index * 18, 53, 13, { fill: C.panel, stroke: C.orange, strokeWidth: 2, radius: 4 });
    add(`<circle cx="${x + 39}" cy="${y + 6 + index * 18}" r="2.5" fill="${C.orange}"/>`);
  }
}

function relayerIcon(x, y) {
  add(`<path d="M ${x + 19} ${y - 28} l -25 35 h 18 l -10 28 32 -42 h -20 Z" fill="#FFD4D4" stroke="${C.red}" stroke-width="2.5"/>`);
}

function shieldIcon(x, y) {
  add(`<path d="M ${x} ${y - 32} l 32 13 v 31 c 0 29 -19 45 -32 53 -13 -8 -32 -24 -32 -53 v -31 Z" fill="#FFF0BF" stroke="${C.amber}" stroke-width="3"/>`);
  add(`<path d="M ${x} ${y - 12} l 7 14 15 2 -11 11 3 15 -14 -7 -14 7 3 -15 -11 -11 15 -2 Z" fill="${C.amber}"/>`);
}

function globeIcon(x, y) {
  add(`<circle cx="${x}" cy="${y}" r="32" fill="#FFF0BF" stroke="${C.amber}" stroke-width="2.5"/>`);
  add(`<ellipse cx="${x}" cy="${y}" rx="15" ry="32" fill="none" stroke="${C.amber}" stroke-width="2"/>`);
  add(`<path d="M ${x - 32} ${y} h 64 M ${x - 26} ${y - 15} h 52 M ${x - 26} ${y + 15} h 52" fill="none" stroke="${C.amber}" stroke-width="2"/>`);
}

add(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="title desc">`);
add('<title id="title">Clairveil Privacy System Architecture</title>');
add('<desc id="desc">Aligned architecture showing the browser trust boundary, ClairveilJS, wallet, local state stores, optional prover, DApp proxy, relayer, and chain query and execution endpoints.</desc>');
add("<defs>");
add('<filter id="shadow" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="6" stdDeviation="9" flood-color="#26344F" flood-opacity="0.09"/></filter>');
for (const color of [C.blue, C.purple, C.green, C.orange, C.red, C.gray, C.amber]) {
  add(`<marker id="arrow-${color.slice(1)}" viewBox="0 0 10 10" markerWidth="7" markerHeight="7" refX="8.6" refY="5" orient="auto-start-reverse" markerUnits="strokeWidth"><path d="M1 1 L9 5 L1 9 L3.2 5 Z" fill="${color}"/></marker>`);
}
add("</defs>");
add(`<rect width="${W}" height="${H}" fill="${C.bg}"/>`);

text(W / 2, 58, "Clairveil 프라이버시 시스템 아키텍처", { size: 45, weight: 800 });
text(W / 2, 99, "기본 흐름: User App → ClairveilJS → Wallet → Chain", {
  size: 20,
  weight: 600,
  fill: C.muted
});

// Client trust boundary and chain endpoint region.
rect(50, 250, 1410, 875, {
  fill: "#F9FBFF",
  stroke: "#9DB7E8",
  strokeWidth: 2,
  radius: 28,
  dash: "10 9"
});
rect(78, 230, 240, 38, { fill: C.panel, stroke: "#9DB7E8", strokeWidth: 1.4, radius: 10 });
text(198, 255, "클라이언트 신뢰 경계", { size: 15, weight: 800, fill: C.blue });

rect(1840, 250, 510, 875, { fill: "#FFFDF8", stroke: "#DDA33F", strokeWidth: 2, radius: 28 });
text(2095, 294, "Chain & Query Endpoints", { size: 27, weight: 800, fill: C.amber });

// Remote prover, outside the trust boundary.
rect(485, 130, 520, 100, { fill: C.greenFill, stroke: C.green, strokeWidth: 2, radius: 18, shadow: true });
proverIcon(535, 180);
header(755, 171, "원격 Prover 서비스 (선택)", "ZK proof 생성 전용 · 외부 신뢰 경계", C.green);

// User application.
rect(90, 405, 280, 340, { fill: C.purpleFill, stroke: C.purple, strokeWidth: 2, radius: 22, shadow: true });
header(230, 450, "사용자 앱 / Browser", "DApp client", C.purple);
userIcon(185, 535);
bullet(122, 615, "SDK 기능 호출", C.purple, { size: 16 });
bullet(122, 650, "privacy root signature", C.purple, { size: 16 });
bullet(122, 685, "wallet context 제공", C.purple, { size: 16 });
bullet(122, 720, "결과 확인", C.purple, { size: 16 });

// ClairveilJS SDK.
rect(450, 320, 590, 440, { fill: C.blueFill, stroke: C.blue, strokeWidth: 2.2, radius: 24, shadow: true });
cubeIcon(488, 374);
header(745, 370, "ClairveilJS SDK", "클라이언트 런타임", C.blueDark);

rect(480, 418, 345, 300, { fill: C.panel, stroke: "#94B9F7", strokeWidth: 1.5, radius: 16 });
text(652, 452, "Core Responsibilities", { size: 19, weight: 800, fill: C.blue });
bullet(501, 490, "proof 응답 contract·binding 검증", C.blue, { size: 14 });
bullet(501, 522, "proverAdapter 연동", C.blue, { size: 14 });
bullet(501, 554, "Reservation lifecycle 관리", C.blue, { size: 14, weight: 700 });
bullet(501, 586, "Wallet 연동 및 서명 요청", C.blue, { size: 14 });
bullet(501, 618, "privacy 연산·transaction build", C.blue, { size: 14 });
bullet(501, 650, "선택적 broadcast helper", C.blue, { size: 14 });
bullet(501, 682, "evidence 기반 reconcile", C.blue, { size: 14 });

rect(846, 418, 164, 150, { fill: C.panel, stroke: "#B8CDF4", strokeWidth: 1.4, radius: 15 });
text(928, 450, "Product-Defined", { size: 16, weight: 800, fill: C.blue });
bullet(866, 486, "정책·수수료", C.blue, { size: 12.5 });
bullet(866, 516, "checkpoint", C.blue, { size: 12.5 });
bullet(866, 546, "UX·재시도", C.blue, { size: 12.5 });

rect(846, 588, 164, 130, { fill: "#F8FBFF", stroke: "#B8CDF4", strokeWidth: 1.4, radius: 15 });
text(928, 620, "SDK 보장", { size: 16, weight: 800, fill: C.blueDark });
text(865, 655, ["• CAS 상태 전이", "• fail-closed", "  note 재사용 방지"], {
  size: 12.5,
  weight: 600,
  anchor: "start"
});

// Wallet.
rect(1120, 405, 300, 300, { fill: C.purpleFill, stroke: C.purple, strokeWidth: 2, radius: 22, shadow: true });
walletIcon(1270, 475);
header(1270, 552, "Wallet", "사용자 지갑", C.purple);
bullet(1162, 620, "transaction 검토", C.purple, { size: 16 });
bullet(1162, 655, "실제 서명 수행", C.purple, { size: 16 });
bullet(1162, 690, "계정·키 관리", C.purple, { size: 16 });

// Local client state stores.
rect(450, 820, 590, 230, { fill: "#F7FBFF", stroke: "#6FA1F5", strokeWidth: 1.8, radius: 22, shadow: true });
databaseIcon(500, 880);
header(745, 870, "Client State Stores", "브라우저 로컬 · private-at-rest", C.blue);
bullet(490, 930, "Note inventory · scan cursor · nullifier 상태", C.blue, { size: 14 });
bullet(490, 966, "Reservation · lease · broadcast evidence", C.blue, { size: 14 });
bullet(785, 930, "Reservation: encrypted IndexedDB + Web Locks", C.blue, { size: 14 });
bullet(785, 966, "다중 탭 CAS · fail-closed 재사용 방지", C.blue, { size: 14 });
text(745, 1018, "저장 키와 private material을 ciphertext와 함께 보관하지 않음", {
  size: 13,
  weight: 700,
  fill: C.blueDark
});

// Optional DApp proxy and relayer, outside the trust boundary.
rect(1500, 690, 300, 205, { fill: C.orangeFill, stroke: C.orange, strokeWidth: 2, radius: 22, shadow: true });
serverIcon(1535, 734);
header(1665, 738, "DApp 서버 (선택)", "API proxy / gateway", C.orange);
bullet(1532, 795, "prover·query endpoint proxy", C.orange, { size: 13.5 });
bullet(1532, 826, "비민감 운영 데이터만 저장", C.orange, { size: 13.5 });
bullet(1532, 857, "privacy material·복호화 note 저장 금지", C.orange, { size: 13, weight: 700 });
text(1650, 884, "서명·권한 주체 아님", { size: 12.5, weight: 700, fill: C.muted });

rect(1500, 945, 300, 170, { fill: C.redFill, stroke: C.red, strokeWidth: 2, radius: 22, shadow: true });
relayerIcon(1540, 990);
header(1665, 985, "Relayer", "별도 제출 주체", C.red);
bullet(1532, 1040, "relay withdraw payload 검증", C.red, { size: 13.5 });
bullet(1532, 1070, "자기 계정으로 제출", C.red, { size: 13.5 });
text(1650, 1098, "재시도·수수료 정책: product-defined", { size: 12.5, weight: 600, fill: C.muted });

// Chain execution endpoint.
rect(1880, 325, 430, 315, { fill: C.amberFill, stroke: "#D9901C", strokeWidth: 1.8, radius: 20, shadow: true });
shieldIcon(1940, 415);
header(2120, 376, "온체인 실행 엔드포인트", "Clairveil Cosmos 모듈 / EVM Precompile", C.amber);
bullet(1918, 500, "transaction 제출·proof 검증", C.amber, { size: 15 });
bullet(1918, 540, "상태 기록 및 이벤트 발생", C.amber, { size: 15 });
bullet(1918, 580, "nullifier 사용 반영", C.amber, { size: 15 });
text(2095, 618, "최종 ZK proof 유효성은 온체인 규칙이 검증", {
  size: 13,
  weight: 700,
  fill: C.amber
});

// Query endpoint.
rect(1880, 750, 430, 310, { fill: C.amberFill, stroke: "#D9901C", strokeWidth: 1.8, radius: 20, shadow: true });
globeIcon(1940, 835);
header(2120, 800, "Query / REST / RPC", "읽기 전용 endpoint", C.amber);
bullet(1918, 905, "privacy scan outputs · nullifiers", C.amber, { size: 15 });
bullet(1918, 945, "events / scan events", C.amber, { size: 15 });
bullet(1918, 985, "Merkle path · circuit/audit/asset config", C.amber, { size: 15 });
text(2095, 1032, "공개 체인 데이터 기반 조회", { size: 13, weight: 700, fill: C.muted });

// Primary flow.
line(370, 550, 450, 550, C.blue, { width: 4.5 });
line(1040, 550, 1120, 550, C.blue, { width: 4.5 });
line(1420, 550, 1880, 550, C.blue, { width: 4.5 });
text(410, 527, "root / context", { size: 11.5, weight: 800, fill: C.blue });
text(1080, 527, "sign 요청", { size: 11.5, weight: 800, fill: C.blue });
tag(1510, 505, 235, "signed transaction", C.blue);
tag(1465, 446, 325, ["SDK helper도 Wallet 서명 후", "broadcast lifecycle을 관리 (선택)"], C.green, { lines: true });

// Prover and local store connections.
line(665, 320, 665, 230, C.green, { width: 3, dash: "8 7" });
line(805, 230, 805, 320, C.green, { width: 3, dash: "8 7" });
tag(678, 242, 114, ["증명 요청", "proof 응답"], C.green, { lines: true });
line(745, 760, 745, 820, C.blue, { width: 3, startArrow: true });
tag(772, 773, 134, "암호화 read/write", C.blue);

// Read-only direct query route.
path("M 1040 682 H 1828 V 950 H 1880", C.gray, { width: 2.8, dash: "8 8" });
tag(1245, 648, 185, "읽기 전용 직접 조회", C.gray);

// Optional DApp proxy route.
path("M 1040 720 C 1200 720 1330 792 1500 792", C.orange, { width: 3, dash: "9 8" });
line(1800, 792, 1880, 792, C.orange, { width: 3, dash: "9 8" });
tag(1125, 740, 205, "선택적 DApp proxy", C.orange);

// Relay withdraw handoff and relayer-owned submission.
path("M 1040 742 C 1210 800 1280 1025 1500 1025", C.red, { width: 3, dash: "9 8" });
tag(1110, 860, 205, "relay payload handoff", C.red);
path("M 1800 1025 H 1820 V 590 H 1880", C.red, { width: 4 });
tag(1685, 590, 190, ["Relayer → Chain", "자기 계정으로 제출"], C.red, { lines: true });

// Public chain data relationship.
line(2095, 640, 2095, 750, C.gray, { width: 2.5, dash: "7 7" });
tag(1980, 676, 230, "공개 chain state 조회", C.gray);

// Critical semantic note.
rect(350, 1165, 1700, 82, { fill: "#F5F9FF", stroke: "#82ACF8", strokeWidth: 1.6, radius: 16 });
add(`<circle cx="392" cy="1206" r="17" fill="${C.blue}"/>`);
text(392, 1213, "i", { size: 21, weight: 800, fill: "#FFFFFF" });
text(430, 1195, "중요: note 상태와 operation 성공은 별개", {
  size: 17,
  weight: 800,
  fill: C.blueDark,
  anchor: "start"
});
text(430, 1225, "ConfirmedSpent는 입력 note 소비 확인이며, payment/operation 성공은 operation_status와 transaction/output evidence로 별도 검증합니다.", {
  size: 14,
  weight: 600,
  anchor: "start"
});

// Legend.
rect(65, 1285, 2270, 130, { fill: C.panel, stroke: "#BBC6D8", strokeWidth: 1.4, radius: 17 });
const legend = [
  [C.blue, "기본 흐름", "User → SDK → Wallet → Chain", ""],
  [C.green, "Prover / SDK helper", "원격 prover · helper orchestration", "9 8"],
  [C.gray, "읽기 전용 조회", "Query / REST / RPC", "8 8"],
  [C.orange, "선택적 Proxy", "DApp server 경유", "9 8"],
  [C.red, "Relay Withdraw", "Relayer 계정 제출", ""]
];
legend.forEach(([color, title, subtitle, dash], index) => {
  const x = 105 + index * 410;
  line(x, 1350, x + 62, 1350, color, { width: dash ? 3 : 4, dash });
  text(x + 84, 1342, title, { size: 14, weight: 800, anchor: "start", fill: color });
  text(x + 84, 1372, subtitle, { size: 12.5, weight: 600, anchor: "start", fill: C.muted });
});
rect(2140, 1328, 34, 34, { fill: "#F9FBFF", stroke: "#9DB7E8", strokeWidth: 1.8, radius: 8, dash: "6 5" });
text(2190, 1342, "신뢰 경계", { size: 14, weight: 800, anchor: "start" });
text(2190, 1372, "클라이언트 로컬", { size: 12.5, weight: 600, anchor: "start", fill: C.muted });

add("</svg>");
await writeFile(OUTPUT, out.join(""), "utf8");
console.log(OUTPUT);
