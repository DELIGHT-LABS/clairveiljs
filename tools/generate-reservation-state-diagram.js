import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const OUTPUT = fileURLToPath(new URL("../docs/assets/note-reservation-lifecycle.svg", import.meta.url));
const RESERVATION_SOURCE = new URL("../src/privacy/reservation.js", import.meta.url);
const CHECK = process.argv.includes("--check");

const W = 2400;
const H = 1560;

const colors = Object.freeze({
  bg: "#F7F9FC",
  panel: "#FFFFFF",
  ink: "#172033",
  muted: "#64748B",
  border: "#D8E1EE",
  blue: "#2563EB",
  blueFill: "#EFF6FF",
  orange: "#F97316",
  orangeFill: "#FFF7ED",
  purple: "#7C3AED",
  purpleFill: "#F5F3FF",
  red: "#EF4444",
  redFill: "#FEF2F2",
  gray: "#64748B",
  grayFill: "#F8FAFC",
  amber: "#D97706",
  amberFill: "#FFFBEB"
});

const styles = Object.freeze({
  confirmed: { color: colors.blue, fill: colors.blueFill },
  recovery: { color: colors.orange, fill: colors.orangeFill },
  uncertain: { color: colors.purple, fill: colors.purpleFill },
  failure: { color: colors.red, fill: colors.redFill },
  neutral: { color: colors.gray, fill: colors.grayFill }
});

const primaryTransitions = [
  ["Discovered", "Available"],
  ["Available", "Reserved"],
  ["Reserved", "Proving"],
  ["Proving", "ProofReady"],
  ["ProofReady", "Submitted"],
  ["Submitted", "ConfirmedSpent"]
];

const groups = [
  {
    title: "계획 · 증명 단계",
    color: colors.blue,
    cards: [
      {
        state: "Discovered",
        tone: "confirmed",
        transitions: [
          { to: "Failed", label: "note 검증 실패", tone: "failure" }
        ]
      },
      {
        state: "Reserved",
        tone: "confirmed",
        transitions: [
          { to: "Released", label: "계획 취소", tone: "neutral" },
          { to: "ReplanRequired", label: "재계획 필요", tone: "recovery" },
          { to: "ManualReview", label: "안전하게 판정 불가", tone: "uncertain" }
        ]
      },
      {
        state: "Proving",
        tone: "confirmed",
        transitions: [
          { to: "Reserved", label: "proof 생성 전 rollback", tone: "confirmed" },
          { to: "ReplanRequired", label: "재계획 필요", tone: "recovery" },
          { to: "ManualReview", label: "lease / 증명 예외", tone: "uncertain" }
        ]
      },
      {
        state: "Released",
        tone: "neutral",
        transitions: [
          { to: "Available", label: "inventory로 복귀", tone: "confirmed" }
        ]
      }
    ]
  },
  {
    title: "제출 · 불확실 단계",
    color: colors.purple,
    cards: [
      {
        state: "ProofReady",
        tone: "confirmed",
        transitions: [
          { to: "Unknown", label: "broadcast 결과 불명", tone: "uncertain" },
          { to: "ConfirmedSpent", label: "reconcile: on-chain spent 확인", tone: "confirmed" },
          { to: "ReplanRequired", label: "wallet 거절 / local proof 폐기", tone: "recovery" },
          { to: "ManualReview", label: "안전하게 판정 불가", tone: "uncertain" }
        ]
      },
      {
        state: "Submitted",
        tone: "confirmed",
        transitions: [
          { to: "Unknown", label: "network 결과 불명", tone: "uncertain" },
          {
            to: "Failed",
            label: "nullifier 미사용 + tx 실패/부재 확인",
            tone: "failure"
          },
          {
            to: "ReplanRequired",
            label: "nullifier 미사용 + tx 실패/부재 확인",
            tone: "recovery"
          },
          { to: "ManualReview", label: "evidence 불충분 또는 충돌", tone: "uncertain" }
        ]
      },
      {
        state: "Unknown",
        tone: "uncertain",
        transitions: [
          { to: "ConfirmedSpent", label: "on-chain spent evidence 확인", tone: "confirmed" },
          {
            to: "Failed",
            label: "nullifier 미사용 + tx 실패/부재 확인",
            tone: "failure"
          },
          {
            to: "ReplanRequired",
            label: "nullifier 미사용 + tx 실패/부재 확인",
            tone: "recovery"
          },
          { to: "ManualReview", label: "안전하게 판정 불가", tone: "uncertain" }
        ]
      }
    ]
  },
  {
    title: "검토 · 복구 결과",
    color: colors.orange,
    cards: [
      {
        state: "ManualReview",
        tone: "uncertain",
        transitions: [
          { to: "ConfirmedSpent", label: "reconcile: chain spent evidence", tone: "confirmed" },
          { to: "Released", label: "operator 승인", tone: "neutral" },
          { to: "ReplanRequired", label: "operator 승인", tone: "recovery" },
          { to: "Failed", label: "operator 승인", tone: "failure" }
        ]
      },
      {
        state: "Failed",
        tone: "failure",
        transitions: [
          { to: "ReplanRequired", label: "재시도 계획", tone: "recovery" }
        ]
      },
      {
        state: "ReplanRequired",
        tone: "recovery",
        transitions: [
          { to: "Reserved", label: "새 계획에서 재예약", tone: "confirmed" },
          { to: "Failed", label: "재계획 실패", tone: "failure" },
          { to: "ManualReview", label: "추가 검토 필요", tone: "uncertain" }
        ]
      }
    ]
  }
];

const escapeXML = value => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;");

const svg = [];
const add = value => svg.push(value);

function text(x, y, value, {
  size = 18,
  weight = 500,
  fill = colors.ink,
  anchor = "middle"
} = {}) {
  const lines = Array.isArray(value) ? value : [value];
  const firstY = y - ((lines.length - 1) * size * 0.6);
  add(`<text x="${x}" y="${firstY}" text-anchor="${anchor}" font-family="Noto Sans KR, Apple SD Gothic Neo, sans-serif" font-size="${size}" font-weight="${weight}" fill="${fill}">`);
  lines.forEach((line, index) => {
    add(`<tspan x="${x}" dy="${index === 0 ? 0 : size * 1.2}">${escapeXML(line)}</tspan>`);
  });
  add("</text>");
}

function panel(x, y, width, height, {
  fill = colors.panel,
  stroke = colors.border,
  radius = 22,
  shadow = false,
  dash = ""
} = {}) {
  add(`<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}" stroke="${stroke}" stroke-width="2"${dash ? ` stroke-dasharray="${dash}"` : ""}${shadow ? ' filter="url(#soft-shadow)"' : ""}/>`);
}

function line(x1, y1, x2, y2, color, { width = 4, arrow = true, dash = "" } = {}) {
  add(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${width}" stroke-linecap="round"${dash ? ` stroke-dasharray="${dash}"` : ""}${arrow ? ` marker-end="url(#arrow-${color.slice(1)})"` : ""}/>`);
}

function sectionTitle(x, y, number, title, color) {
  add(`<circle cx="${x}" cy="${y}" r="22" fill="${color}"/>`);
  text(x, y + 7, number, { size: 21, weight: 700, fill: "#FFFFFF" });
  text(x + 38, y + 8, title, { size: 27, weight: 700, fill: color, anchor: "start" });
}

function stateNode(name, x, y, {
  tone = "confirmed",
  width = name === "ConfirmedSpent" ? 236 : 190,
  height = 70,
  terminal = false
} = {}) {
  const style = styles[tone];
  panel(x - width / 2, y - height / 2, width, height, {
    fill: style.fill,
    stroke: style.color,
    radius: 16,
    shadow: true
  });
  text(x, y + 8, name, { size: 23, weight: 700, fill: style.color });
  if (terminal) {
    panel(x + width / 2 - 80, y - height / 2 - 12, 72, 25, {
      fill: colors.panel,
      stroke: style.color,
      radius: 13
    });
    text(x + width / 2 - 44, y - height / 2 + 5, "TERMINAL", {
      size: 10,
      weight: 700,
      fill: style.color
    });
  }
  return { left: x - width / 2, right: x + width / 2, x, y, width, height };
}

function targetPill(x, y, width, transition) {
  const style = styles[transition.tone];
  panel(x, y, width, 38, {
    fill: style.fill,
    stroke: style.color,
    radius: 13,
    dash: "7 6"
  });
  text(x + 14, y + 25, transition.to, {
    size: transition.to.length > 15 ? 15 : 16,
    weight: 700,
    fill: style.color,
    anchor: "start"
  });
  text(x + width - 13, y + 25, "↗", {
    size: 14,
    weight: 700,
    fill: style.color,
    anchor: "end"
  });
}

function transitionTile(x, y, width, transition) {
  const style = styles[transition.tone];
  const label = transition.label.length > 30
    ? transition.label.replace(" + ", " +\n").split("\n")
    : transition.label;
  text(x + 8, y + 18, label, {
    size: 13,
    weight: 600,
    fill: colors.muted,
    anchor: "start"
  });
  const pillY = y + 36;
  line(x + 8, pillY + 19, x + 71, pillY + 19, style.color, {
    width: 3,
    dash: transition.special ? "8 6" : ""
  });
  targetPill(x + 83, pillY, width - 91, transition);
  if (transition.special) {
    panel(x + width - 72, y + 2, 64, 22, {
      fill: colors.panel,
      stroke: colors.gray,
      radius: 11
    });
    text(x + width - 40, y + 17, "SPECIAL", {
      size: 9,
      weight: 700,
      fill: colors.gray
    });
  }
}

function sourceCard(x, y, width, card) {
  const rows = Math.ceil(card.transitions.length / 2);
  const height = 78 + rows * 76 + 13;
  panel(x, y, width, height, { stroke: colors.border, shadow: true });
  const style = styles[card.tone];
  panel(x + 18, y + 17, 220, 48, {
    fill: style.fill,
    stroke: style.color,
    radius: 14
  });
  text(x + 34, y + 49, card.state, {
    size: card.state.length > 14 ? 18 : 20,
    weight: 700,
    fill: style.color,
    anchor: "start"
  });
  text(x + width - 20, y + 47, `${card.transitions.length}개 전이`, {
    size: 13,
    weight: 600,
    fill: colors.muted,
    anchor: "end"
  });
  const gap = 14;
  const tileWidth = (width - 36 - gap) / 2;
  card.transitions.forEach((transition, index) => {
    const col = index % 2;
    const row = Math.floor(index / 2);
    transitionTile(
      x + 18 + col * (tileWidth + gap),
      y + 77 + row * 76,
      tileWidth,
      transition
    );
  });
  return height;
}

async function assertCodeAlignment() {
  const source = await readFile(RESERVATION_SOURCE, "utf8");
  const block = source.match(/const allowedReservationTransitions = new Set\(\[([\s\S]*?)\]\);/u)?.[1];
  if (!block) throw new Error("allowedReservationTransitions was not found");
  const codeTransitions = [...block.matchAll(/"([^"\\]+)\\x00([^"\\]+)"/gu)]
    .map(match => `${match[1]}→${match[2]}`)
    .sort();
  const detailTransitions = groups.flatMap(group => group.cards.flatMap(card =>
    card.transitions.filter(transition => !transition.special).map(transition => [card.state, transition.to])
  ));
  const diagramTransitions = [...primaryTransitions, ...detailTransitions]
    .map(([from, to]) => `${from}→${to}`)
    .sort();
  const missing = codeTransitions.filter(edge => !diagramTransitions.includes(edge));
  const extra = diagramTransitions.filter(edge => !codeTransitions.includes(edge));
  if (missing.length || extra.length || new Set(diagramTransitions).size !== codeTransitions.length) {
    throw new Error(`diagram transition mismatch\nmissing: ${missing.join(", ")}\nextra: ${extra.join(", ")}`);
  }
}

await assertCodeAlignment();

add(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="title desc">`);
add('<title id="title">ClairveilJS Note Reservation Lifecycle State Diagram</title>');
add('<desc id="desc">Normal note reservation lifecycle and every code-aligned exception, recovery, review, and failure transition.</desc>');
add("<defs>");
add('<filter id="soft-shadow" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="5" stdDeviation="8" flood-color="#26344F" flood-opacity="0.09"/></filter>');
for (const style of Object.values(styles)) {
  add(`<marker id="arrow-${style.color.slice(1)}" viewBox="0 0 10 10" markerWidth="7" markerHeight="7" refX="8.6" refY="5" orient="auto-start-reverse" markerUnits="strokeWidth"><path d="M1 1 L9 5 L1 9 L3.2 5 Z" fill="${style.color}"/></marker>`);
}
add("</defs>");
add(`<rect width="${W}" height="${H}" fill="${colors.bg}"/>`);

text(W / 2, 58, "Note Reservation Lifecycle State Diagram", { size: 45, weight: 800 });
text(W / 2, 96, "ClairveilJS SDK 예약 상태 머신 · code-aligned transitions", {
  size: 20,
  fill: colors.muted
});

panel(48, 130, 2304, 275, { stroke: "#BCD0F5", shadow: true });
sectionTitle(88, 170, "1", "주요 흐름 · Primary Flow", colors.blue);

const primaryY = 292;
const primaryXs = [300, 610, 920, 1230, 1540, 1850, 2180];
const names = ["Discovered", "Available", "Reserved", "Proving", "ProofReady", "Submitted", "ConfirmedSpent"];
const labels = [
  "검증된 note 발견",
  ["plan에서", "note 선택"],
  "batch lease 획득",
  ["proof 생성 및", "checkpoint 완료"],
  ["제출 identity", "metadata 기록"],
  ["on-chain spent", "evidence 확인"]
];
add(`<circle cx="88" cy="${primaryY}" r="16" fill="#111827"/>`);
text(88, primaryY + 58, "[*]", { size: 15, weight: 700, fill: colors.muted });
const primaryNodes = names.map((name, index) => stateNode(name, primaryXs[index], primaryY, {
  terminal: name === "ConfirmedSpent",
  width: name === "ConfirmedSpent" ? 238 : 194
}));
line(116, primaryY, primaryNodes[0].left - 18, primaryY, colors.blue, { width: 5 });
primaryNodes.slice(0, -1).forEach((node, index) => {
  const next = primaryNodes[index + 1];
  line(node.right + 18, primaryY, next.left - 18, primaryY, colors.blue, { width: 5 });
  text((node.right + next.left) / 2, 225, labels[index], { size: 15, weight: 600 });
});
text(2180, 368, "입력 note 소비 확인", { size: 15, weight: 700, fill: colors.red });

sectionTitle(70, 455, "2", "예외·복구 전이 · Exception & Recovery Map", colors.purple);
text(2328, 463, "점선 목적지 = 위 또는 다른 카드의 동일 상태 참조", {
  size: 14,
  fill: colors.muted,
  anchor: "end"
});

const columnX = [48, 833, 1618];
const columnWidth = 734;
const cardsY = 535;
groups.forEach((group, groupIndex) => {
  const x = columnX[groupIndex];
  text(x + columnWidth / 2, 505, group.title, {
    size: 22,
    weight: 700,
    fill: group.color
  });
  let y = cardsY;
  group.cards.forEach(card => {
    y += sourceCard(x, y, columnWidth, card) + 14;
  });
});

panel(48, 1420, 2304, 100, { stroke: colors.border });
const legend = [
  ["confirmed", "정상·확정"],
  ["recovery", "복구·재계획"],
  ["uncertain", "검토·불확실"],
  ["failure", "실패"],
  ["neutral", "release·중립"]
];
legend.forEach(([tone, label], index) => {
  const x = 88 + index * 300;
  line(x, 1470, x + 62, 1470, styles[tone].color, { width: 4 });
  text(x + 84, 1477, label, { size: 16, weight: 600, anchor: "start" });
});
text(1610, 1457, "ConfirmedSpent = 입력 note 소비 확인", {
  size: 15,
  weight: 700,
  fill: colors.red,
  anchor: "start"
});
text(1610, 1486, "operation 성공 matcher는 txHash/txBytesHash와 output evidence를 비교 · transport 구분 없음", {
  size: 13,
  fill: colors.muted,
  anchor: "start"
});
text(1610, 1510, "Proving 결과가 불명확하면 release하지 않고 ManualReview로 격리", {
  size: 12.5,
  fill: colors.muted,
  anchor: "start"
});

add("</svg>");
const generated = svg.join("");
if (CHECK) {
  const committed = await readFile(OUTPUT, "utf8");
  if (committed !== generated) {
    throw new Error("reservation lifecycle SVG is stale; run npm run docs:diagram:reservation and commit the result");
  }
  console.log(`up to date: ${OUTPUT}`);
} else {
  await writeFile(OUTPUT, generated, "utf8");
  console.log(OUTPUT);
}
