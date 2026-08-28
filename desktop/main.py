"""
AI DevSecOps Code Reviewer - desktop GUI.

PySide6 desktop interface for the existing analysis backend.

Backend contract:

    analyze_code(code=code, language=language) -> {
        "summary": str,
        "findings": [
            {
                "title": str,
                "category": str,
                "severity": str,
                "evidence": str,
                "impact": str,
                "remediation": str,
                "source": list[str] | str,
                "line_start": int | None,
                "line_end": int | None,
            },
            ...
        ],
        "policy": {
            "decision": str,
            "highest_severity": str | None,
        },
    }
"""

import sys

from PySide6.QtCore import (
    Qt,
    QObject,
    QThread,
    Signal,
    Slot,
    QRect,
    QSize,
    QRegularExpression,
    QTimer,
)
from PySide6.QtGui import (
    QFont,
    QColor,
    QPainter,
    QTextFormat,
    QTextCharFormat,
    QSyntaxHighlighter,
    QKeySequence,
    QShortcut,
    QGuiApplication,
)
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QPushButton,
    QToolButton,
    QPlainTextEdit,
    QTextEdit,
    QScrollArea,
    QFrame,
    QProgressBar,
)

from backend.analysis_service import analyze_code


# ==========================================================
# Palette
# ==========================================================

COLORS = {
    "bg": "#0f1117",
    "panel": "#161923",
    "panel_alt": "#1b1f2c",
    "border": "#2a2f3d",
    "text": "#e6e8ef",
    "text_dim": "#9aa1b4",
    "accent": "#5eb0ff",
    "accent_dim": "#3a7fbf",
    "good": "#3ecf8e",
}

SEVERITY_STYLES = {
    "CRITICAL": ("#4a1420", "#ff6b81", "#7a2436", "●"),
    "HIGH": ("#3d1a17", "#ff8a65", "#6b2e28", "●"),
    "ERROR": ("#3d1a17", "#ff8a65", "#6b2e28", "●"),
    "MEDIUM": ("#3d2f12", "#ffc266", "#6b5420", "●"),
    "WARNING": ("#12283d", "#66b3ff", "#20456b", "●"),
    "LOW": ("#132a24", "#5ed9b0", "#1f4a3d", "●"),
}

DEFAULT_SEVERITY_STYLE = (
    "#20232e",
    "#c3c8d6",
    "#343849",
    "●",
)

MONOSPACE_FAMILY = (
    "Consolas, 'Cascadia Mono', 'JetBrains Mono', "
    "'Courier New', monospace"
)


def severity_style(severity: str):
    return SEVERITY_STYLES.get(
        (severity or "").upper(),
        DEFAULT_SEVERITY_STYLE,
    )


def normalize_sources(source) -> list[str]:
    """
    Normalize backend source values.

    Supports:
        ["ai", "semgrep"]
        "ai"
        None
    """
    if source is None:
        return []

    if isinstance(source, str):
        return [source]

    if isinstance(source, (list, tuple, set)):
        return [str(item) for item in source if item]

    return [str(source)]


# ==========================================================
# Global stylesheet
# ==========================================================

def build_stylesheet() -> str:
    return f"""
    QMainWindow {{
        background-color: {COLORS['bg']};
    }}

    QWidget {{
        color: {COLORS['text']};
        font-family: 'Segoe UI', 'Inter', sans-serif;
        font-size: 13px;
    }}

    QLabel#appTitle {{
        font-size: 20px;
        font-weight: 600;
        color: {COLORS['text']};
    }}

    QLabel#appSubtitle {{
        color: {COLORS['text_dim']};
        font-size: 12px;
    }}

    QLabel#sectionLabel {{
        color: {COLORS['text_dim']};
        font-size: 11px;
        font-weight: 600;
    }}

    QFrame#panel {{
        background-color: {COLORS['panel']};
        border: 1px solid {COLORS['border']};
        border-radius: 10px;
    }}

    QFrame#card {{
        background-color: {COLORS['panel_alt']};
        border: 1px solid {COLORS['border']};
        border-radius: 10px;
    }}

    QComboBox {{
        background-color: {COLORS['panel_alt']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 5px 8px;
        min-height: 22px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {COLORS['panel_alt']};
        border: 1px solid {COLORS['border']};
        selection-background-color: {COLORS['accent_dim']};
    }}

    QPushButton#reviewButton {{
        background-color: {COLORS['accent']};
        color: #0b1220;
        font-weight: 600;
        border: none;
        border-radius: 8px;
        padding: 10px 20px;
    }}

    QPushButton#reviewButton:disabled {{
        background-color: {COLORS['accent_dim']};
        color: #223045;
    }}

    QPushButton#reviewButton:hover:!disabled {{
        background-color: #78c0ff;
    }}

    QPushButton#secondaryButton {{
        background-color: transparent;
        color: {COLORS['text_dim']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 6px 12px;
    }}

    QPushButton#secondaryButton:hover {{
        color: {COLORS['text']};
        border-color: {COLORS['accent_dim']};
    }}

    QToolButton#copyButton {{
        background-color: transparent;
        color: {COLORS['text_dim']};
        border: 1px solid {COLORS['border']};
        border-radius: 5px;
        padding: 2px 8px;
        font-size: 11px;
    }}

    QToolButton#copyButton:hover {{
        color: {COLORS['accent']};
        border-color: {COLORS['accent_dim']};
    }}

    QScrollArea {{
        border: none;
        background: transparent;
    }}

    QProgressBar {{
        background-color: {COLORS['panel_alt']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        height: 6px;
        text-align: center;
    }}

    QProgressBar::chunk {{
        background-color: {COLORS['accent']};
        border-radius: 4px;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
    }}

    QScrollBar::handle:vertical {{
        background: {COLORS['border']};
        border-radius: 5px;
        min-height: 24px;
    }}

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    """


# ==========================================================
# Code editor
# ==========================================================

class LineNumberArea(QWidget):

    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return QSize(
            self.editor.line_number_area_width(),
            0,
        )

    def paintEvent(self, event):
        self.editor.paint_line_numbers(event)


class PythonHighlighter(QSyntaxHighlighter):

    KEYWORDS = [
        "False", "None", "True", "and", "as", "assert", "async",
        "await", "break", "class", "continue", "def", "del",
        "elif", "else", "except", "finally", "for", "from",
        "global", "if", "import", "in", "is", "lambda",
        "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield",
    ]

    def __init__(self, document):
        super().__init__(document)

        self.rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(
            QColor("#c586c0")
        )
        keyword_format.setFontWeight(
            QFont.Bold
        )

        for keyword in self.KEYWORDS:
            self.rules.append(
                (
                    QRegularExpression(
                        rf"\b{keyword}\b"
                    ),
                    keyword_format,
                )
            )

        builtin_format = QTextCharFormat()
        builtin_format.setForeground(
            QColor("#4ec9b0")
        )

        self.rules.append(
            (
                QRegularExpression(r"\bself\b"),
                builtin_format,
            )
        )

        self.rules.append(
            (
                QRegularExpression(
                    r"\b(print|len|range|str|int|float|dict|list|set|tuple)\b"
                ),
                builtin_format,
            )
        )

        decorator_format = QTextCharFormat()
        decorator_format.setForeground(
            QColor("#dcdcaa")
        )

        self.rules.append(
            (
                QRegularExpression(r"@\w+"),
                decorator_format,
            )
        )

        number_format = QTextCharFormat()
        number_format.setForeground(
            QColor("#b5cea8")
        )

        self.rules.append(
            (
                QRegularExpression(
                    r"\b[0-9]+(\.[0-9]+)?\b"
                ),
                number_format,
            )
        )

        function_format = QTextCharFormat()
        function_format.setForeground(
            QColor("#dcdcaa")
        )

        self.rules.append(
            (
                QRegularExpression(
                    r"\bdef\s+(\w+)"
                ),
                function_format,
            )
        )

        self.string_format = QTextCharFormat()
        self.string_format.setForeground(
            QColor("#ce9178")
        )

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(
            QColor("#6a9955")
        )
        self.comment_format.setFontItalic(True)

        self.single_quote = QRegularExpression(
            r"'[^'\\]*(\\.[^'\\]*)*'"
        )

        self.double_quote = QRegularExpression(
            r'"[^"\\]*(\\.[^"\\]*)*"'
        )

        self.comment_pattern = QRegularExpression(
            r"#[^\n]*"
        )

    def highlightBlock(self, text):

        for pattern, text_format in self.rules:

            iterator = pattern.globalMatch(text)

            while iterator.hasNext():

                match = iterator.next()

                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    text_format,
                )

        for pattern in (
            self.single_quote,
            self.double_quote,
        ):

            iterator = pattern.globalMatch(text)

            while iterator.hasNext():

                match = iterator.next()

                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    self.string_format,
                )

        iterator = self.comment_pattern.globalMatch(
            text
        )

        while iterator.hasNext():

            match = iterator.next()

            self.setFormat(
                match.capturedStart(),
                match.capturedLength(),
                self.comment_format,
            )


class CodeEditor(QPlainTextEdit):

    def __init__(self, parent=None):

        super().__init__(parent)

        self.line_number_area = LineNumberArea(
            self
        )

        font = QFont()

        font.setFamilies([
            "Consolas",
            "Cascadia Mono",
            "JetBrains Mono",
            "Courier New",
        ])

        font.setStyleHint(
            QFont.Monospace
        )

        font.setPointSize(11)

        self.setFont(font)

        self.setPlaceholderText(
            "Paste your Python code here..."
        )

        self.setTabStopDistance(
            4 * self.fontMetrics().horizontalAdvance(
                " "
            )
        )

        self.setLineWrapMode(
            QPlainTextEdit.NoWrap
        )

        self.setFrameShape(
            QFrame.NoFrame
        )

        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: #10131b;
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 10px;
                padding: 10px;
                selection-background-color: {COLORS['accent_dim']};
            }}
        """)

        self.highlighter = PythonHighlighter(
            self.document()
        )

        self.blockCountChanged.connect(
            self.update_line_number_area_width
        )

        self.updateRequest.connect(
            self.update_line_number_area
        )

        self.cursorPositionChanged.connect(
            self.highlight_current_line
        )

        self.update_line_number_area_width(0)
        self.highlight_current_line()

    def line_number_area_width(self) -> int:

        digits = max(
            2,
            len(
                str(
                    max(
                        1,
                        self.blockCount()
                    )
                )
            ),
        )

        return (
            12
            + self.fontMetrics().horizontalAdvance(
                "9"
            ) * digits
        )

    def update_line_number_area_width(self, _):

        self.setViewportMargins(
            self.line_number_area_width(),
            0,
            0,
            0,
        )

    def update_line_number_area(
        self,
        rect,
        dy,
    ):

        if dy:

            self.line_number_area.scroll(
                0,
                dy,
            )

        else:

            self.line_number_area.update(
                0,
                rect.y(),
                self.line_number_area.width(),
                rect.height(),
            )

        if rect.contains(
            self.viewport().rect()
        ):

            self.update_line_number_area_width(0)

    def resizeEvent(self, event):

        super().resizeEvent(event)

        rect = self.contentsRect()

        self.line_number_area.setGeometry(
            QRect(
                rect.left(),
                rect.top(),
                self.line_number_area_width(),
                rect.height(),
            )
        )

    def paint_line_numbers(self, event):

        painter = QPainter(
            self.line_number_area
        )

        painter.fillRect(
            event.rect(),
            QColor("#0d0f16"),
        )

        block = self.firstVisibleBlock()

        block_number = block.blockNumber()

        top = round(
            self.blockBoundingGeometry(block)
            .translated(self.contentOffset())
            .top()
        )

        bottom = (
            top
            + round(
                self.blockBoundingRect(block)
                .height()
            )
        )

        painter.setPen(
            QColor(COLORS["text_dim"])
        )

        while (
            block.isValid()
            and top <= event.rect().bottom()
        ):

            if (
                block.isVisible()
                and bottom >= event.rect().top()
            ):

                painter.drawText(
                    0,
                    top,
                    self.line_number_area.width() - 6,
                    self.fontMetrics().height(),
                    Qt.AlignRight,
                    str(block_number + 1),
                )

            block = block.next()

            top = bottom

            if block.isValid():

                bottom = (
                    top
                    + round(
                        self.blockBoundingRect(block)
                        .height()
                    )
                )

            block_number += 1

    def highlight_current_line(self):

        selections = []

        if not self.isReadOnly():

            # FIX:
            # ExtraSelection belongs to QTextEdit in
            # PySide6, not QPlainTextEdit.
            selection = QTextEdit.ExtraSelection()

            selection.format.setBackground(
                QColor("#161c29")
            )

            selection.format.setProperty(
                QTextFormat.FullWidthSelection,
                True,
            )

            selection.cursor = self.textCursor()

            selection.cursor.clearSelection()

            selections.append(selection)

        self.setExtraSelections(
            selections
        )


# ==========================================================
# UI helpers
# ==========================================================

def make_badge(
    text: str,
    bg: str,
    fg: str,
    border: str,
) -> QLabel:

    label = QLabel(text)

    label.setStyleSheet(f"""
        QLabel {{
            background-color: {bg};
            color: {fg};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 3px 10px;
            font-weight: 600;
            font-size: 11px;
        }}
    """)

    return label


def make_status_dot(
    color: str,
) -> QLabel:

    label = QLabel("●")

    label.setStyleSheet(
        f"color: {color}; font-size: 10px;"
    )

    return label


def copy_button(get_text) -> QToolButton:

    button = QToolButton()

    button.setObjectName(
        "copyButton"
    )

    button.setText("Copy")

    button.setCursor(
        Qt.PointingHandCursor
    )

    def do_copy():

        text = get_text()

        QGuiApplication.clipboard().setText(
            text or ""
        )

        original = button.text()

        button.setText("Copied")

        QTimer.singleShot(
            1200,
            lambda: button.setText(original),
        )

    button.clicked.connect(
        do_copy
    )

    return button


def plain_text_box(
    text: str,
    monospace: bool = False,
) -> QPlainTextEdit:
    """
    Create a read-only plain-text output box.

    This deliberately uses QPlainTextEdit rather than
    QLabel so the output can be selected and copied
    exactly as plain text.
    """

    body = QPlainTextEdit()

    body.setReadOnly(True)

    body.setPlainText(
        text if text else "-"
    )

    body.setLineWrapMode(
        QPlainTextEdit.WidgetWidth
    )

    body.setMinimumHeight(
        55
    )

    if monospace:

        body.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: #10131b;
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px;
                font-family: {MONOSPACE_FAMILY};
                font-size: 12px;
                color: #d7dbe6;
            }}
        """)

    else:

        body.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: #10131b;
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px;
                font-family: 'Segoe UI', 'Inter', sans-serif;
                font-size: 12px;
                color: {COLORS['text']};
            }}
        """)

    # Adjust height to the amount of text.
    document_height = (
        body.document().documentLayout().documentSize().height()
    )

    body.setFixedHeight(
        max(
            55,
            min(
                220,
                int(document_height + 25)
            ),
        )
    )

    return body


def section_block(
    title: str,
    body_text: str,
    monospace: bool = False,
    with_copy: bool = False,
):

    container = QWidget()

    layout = QVBoxLayout(
        container
    )

    layout.setContentsMargins(
        0,
        0,
        0,
        0,
    )

    layout.setSpacing(4)

    header_row = QHBoxLayout()

    header_row.setContentsMargins(
        0,
        0,
        0,
        0,
    )

    header = QLabel(
        title.upper()
    )

    header.setObjectName(
        "sectionLabel"
    )

    header_row.addWidget(
        header
    )

    header_row.addStretch()

    body = plain_text_box(
        body_text,
        monospace=monospace,
    )

    if with_copy:

        header_row.addWidget(
            copy_button(
                lambda: body.toPlainText()
            )
        )

    layout.addLayout(
        header_row
    )

    layout.addWidget(
        body
    )

    return container


# ==========================================================
# Finding card
# ==========================================================

class FindingCard(QFrame):

    def __init__(
        self,
        finding: dict,
        parent=None,
    ):

        super().__init__(parent)

        self.finding = finding

        self.setObjectName(
            "card"
        )

        severity = (
            finding.get("severity")
            or ""
        ).upper()

        bg, fg, border, icon = severity_style(
            severity
        )

        sources = normalize_sources(
            finding.get("source")
        )

        outer = QVBoxLayout(
            self
        )

        outer.setContentsMargins(
            14,
            12,
            14,
            12,
        )

        outer.setSpacing(
            10
        )

        # --------------------------------------------------
        # Header
        # --------------------------------------------------

        header_row = QHBoxLayout()

        header_row.setSpacing(
            10
        )

        severity_badge = make_badge(
            f"{icon} {severity or 'UNKNOWN'}",
            bg,
            fg,
            border,
        )

        header_row.addWidget(
            severity_badge
        )

        title_label = QLabel(
            finding.get("title")
            or "Untitled finding"
        )

        title_label.setStyleSheet(
            "font-size: 14px; font-weight: 600;"
        )

        title_label.setWordWrap(
            True
        )

        header_row.addWidget(
            title_label,
            stretch=1,
        )

        source_text = self._format_source(
            sources
        )

        source_bg = (
            COLORS["panel"]
            if len(sources) < 2
            else "#12331f"
        )

        source_fg = (
            COLORS["accent"]
            if len(sources) < 2
            else COLORS["good"]
        )

        source_badge = make_badge(
            source_text,
            source_bg,
            source_fg,
            COLORS["border"],
        )

        header_row.addWidget(
            source_badge
        )

        # --------------------------------------------------
        # Copy whole finding button
        # --------------------------------------------------

        self.copy_finding_button = QToolButton()

        self.copy_finding_button.setObjectName(
            "copyButton"
        )

        self.copy_finding_button.setText(
            "Copy Finding"
        )

        self.copy_finding_button.setCursor(
            Qt.PointingHandCursor
        )

        self.copy_finding_button.clicked.connect(
            self.copy_entire_finding
        )

        header_row.addWidget(
            self.copy_finding_button
        )

        # --------------------------------------------------
        # Toggle button
        # --------------------------------------------------

        self.toggle_button = QToolButton()

        self.toggle_button.setObjectName(
            "copyButton"
        )

        self.toggle_button.setText(
            "▼"
        )

        self.toggle_button.setCursor(
            Qt.PointingHandCursor
        )

        self.toggle_button.clicked.connect(
            self.toggle_details
        )

        header_row.addWidget(
            self.toggle_button
        )

        outer.addLayout(
            header_row
        )

        # --------------------------------------------------
        # Category
        # --------------------------------------------------

        category = finding.get(
            "category"
        )

        if category:

            category_label = QLabel(
                f"Category: {category}"
            )

            category_label.setStyleSheet(
                f"""
                color: {COLORS['text_dim']};
                font-size: 11px;
                """
            )

            outer.addWidget(
                category_label
            )

        # --------------------------------------------------
        # Details
        # --------------------------------------------------

        self.details = QWidget()

        details_layout = QVBoxLayout(
            self.details
        )

        details_layout.setContentsMargins(
            0,
            4,
            0,
            0,
        )

        details_layout.setSpacing(
            10
        )

        evidence = (
            finding.get("evidence")
            or ""
        )

        impact = (
            finding.get("impact")
            or ""
        )

        remediation = (
            finding.get("remediation")
            or ""
        )

        details_layout.addWidget(
            section_block(
                "Evidence",
                evidence,
                monospace=True,
                with_copy=True,
            )
        )

        details_layout.addWidget(
            section_block(
                "Impact",
                impact,
                monospace=False,
                with_copy=True,
            )
        )

        details_layout.addWidget(
            section_block(
                "Remediation",
                remediation,
                monospace=True,
                with_copy=True,
            )
        )

        # --------------------------------------------------
        # Line information
        # --------------------------------------------------

        line_start = finding.get(
            "line_start"
        )

        line_end = finding.get(
            "line_end"
        )

        if line_start is not None:

            if (
                line_end
                and line_end != line_start
            ):

                line_text = (
                    f"Lines {line_start}–{line_end}"
                )

            else:

                line_text = (
                    f"Line {line_start}"
                )

            line_label = QLabel(
                line_text
            )

            line_label.setStyleSheet(
                f"""
                color: {COLORS['text_dim']};
                font-size: 11px;
                """
            )

            details_layout.addWidget(
                line_label
            )

        outer.addWidget(
            self.details
        )

    @staticmethod
    def _format_source(
        sources: list[str],
    ) -> str:

        labels = [
            source.upper()
            for source in sources
        ]

        if len(labels) >= 2:

            return " + ".join(
                labels
            )

        if labels:

            return labels[0]

        return "UNKNOWN"

    def get_plain_text(self) -> str:
        """
        Build a completely plain-text representation
        of the finding.
        """

        severity = (
            self.finding.get("severity")
            or "UNKNOWN"
        ).upper()

        title = (
            self.finding.get("title")
            or "Untitled finding"
        )

        category = (
            self.finding.get("category")
            or "Uncategorized"
        )

        sources = normalize_sources(
            self.finding.get("source")
        )

        source_text = self._format_source(
            sources
        )

        evidence = (
            self.finding.get("evidence")
            or "-"
        )

        impact = (
            self.finding.get("impact")
            or "-"
        )

        remediation = (
            self.finding.get("remediation")
            or "-"
        )

        line_start = self.finding.get(
            "line_start"
        )

        line_end = self.finding.get(
            "line_end"
        )

        if line_start is not None:

            if (
                line_end
                and line_end != line_start
            ):

                line_text = (
                    f"Lines {line_start}-{line_end}"
                )

            else:

                line_text = (
                    f"Line {line_start}"
                )

        else:

            line_text = "-"

        return (
            "==================================================\n"
            "FINDING\n"
            "==================================================\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n"
            f"Category: {category}\n"
            f"Source: {source_text}\n"
            f"Location: {line_text}\n"
            "\n"
            "EVIDENCE\n"
            "--------------------------------------------------\n"
            f"{evidence}\n"
            "\n"
            "IMPACT\n"
            "--------------------------------------------------\n"
            f"{impact}\n"
            "\n"
            "REMEDIATION\n"
            "--------------------------------------------------\n"
            f"{remediation}\n"
        )

    def copy_entire_finding(self):

        text = self.get_plain_text()

        QGuiApplication.clipboard().setText(
            text
        )

        original = (
            self.copy_finding_button.text()
        )

        self.copy_finding_button.setText(
            "Copied"
        )

        QTimer.singleShot(
            1200,
            lambda: self.copy_finding_button.setText(
                original
            ),
        )

    def toggle_details(self):

        visible = (
            not self.details.isVisible()
        )

        self.details.setVisible(
            visible
        )

        self.toggle_button.setText(
            "▼" if visible else "▶"
        )


# ==========================================================
# Empty / error states
# ==========================================================

def build_empty_state_card() -> QFrame:

    card = QFrame()

    card.setObjectName(
        "card"
    )

    layout = QVBoxLayout(
        card
    )

    layout.setContentsMargins(
        20,
        24,
        20,
        24,
    )

    layout.setSpacing(
        6
    )

    layout.setAlignment(
        Qt.AlignCenter
    )

    icon = QLabel(
        "✓"
    )

    icon.setAlignment(
        Qt.AlignCenter
    )

    icon.setStyleSheet(
        f"""
        color: {COLORS['good']};
        font-size: 22px;
        """
    )

    layout.addWidget(
        icon
    )

    title = QLabel(
        "No issues detected"
    )

    title.setAlignment(
        Qt.AlignCenter
    )

    title.setStyleSheet(
        "font-size: 14px; font-weight: 600;"
    )

    layout.addWidget(
        title
    )

    subtitle = QLabel(
        "The submitted code passed "
        "the available review checks."
    )

    subtitle.setAlignment(
        Qt.AlignCenter
    )

    subtitle.setStyleSheet(
        f"""
        color: {COLORS['text_dim']};
        font-size: 12px;
        """
    )

    layout.addWidget(
        subtitle
    )

    return card


def build_error_card(
    message: str,
) -> QFrame:

    card = QFrame()

    card.setObjectName(
        "card"
    )

    card.setStyleSheet(
        """
        QFrame#card {
            border-color: #6b2e28;
        }
        """
    )

    layout = QVBoxLayout(
        card
    )

    layout.setContentsMargins(
        16,
        14,
        16,
        14,
    )

    layout.setSpacing(
        6
    )

    title = QLabel(
        "⚠ Review failed"
    )

    title.setStyleSheet(
        """
        color: #ff8a65;
        font-size: 14px;
        font-weight: 600;
        """
    )

    layout.addWidget(
        title
    )

    subtitle = QLabel(
        "An error occurred while analyzing "
        "the submitted code."
    )

    subtitle.setStyleSheet(
        f"""
        color: {COLORS['text_dim']};
        font-size: 12px;
        """
    )

    layout.addWidget(
        subtitle
    )

    layout.addWidget(
        section_block(
            "Technical details",
            message,
            monospace=True,
            with_copy=True,
        )
    )

    return card


# ==========================================================
# Overview panel
# ==========================================================

class OverviewPanel(QFrame):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.setObjectName(
            "panel"
        )

        self.setMinimumWidth(
            220
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            16,
            14,
            16,
            14,
        )

        layout.setSpacing(
            10
        )

        header = QLabel(
            "REVIEW OVERVIEW"
        )

        header.setObjectName(
            "sectionLabel"
        )

        layout.addWidget(
            header
        )

        self.decision_badge = make_badge(
            "NOT YET RUN",
            COLORS["panel_alt"],
            COLORS["text_dim"],
            COLORS["border"],
        )

        layout.addWidget(
            self.decision_badge,
            alignment=Qt.AlignLeft,
        )

        self.stats_layout = QVBoxLayout()

        self.stats_layout.setSpacing(
            6
        )

        layout.addLayout(
            self.stats_layout
        )

        layout.addStretch()

        self._render_stats(
            total=None,
            source_counts={},
            category_counts={},
            highest=None,
        )

    def _replace_decision_badge(
        self,
        text: str,
        bg: str,
        fg: str,
        border: str,
    ):

        old_badge = (
            self.decision_badge
        )

        new_badge = make_badge(
            text,
            bg,
            fg,
            border,
        )

        self.decision_badge = (
            new_badge
        )

        layout = self.layout()

        index = layout.indexOf(
            old_badge
        )

        if index < 0:
            index = 1

        layout.removeWidget(
            old_badge
        )

        old_badge.deleteLater()

        layout.insertWidget(
            index,
            new_badge,
            alignment=Qt.AlignLeft,
        )

    def _stat_row(
        self,
        label: str,
        value: str,
    ) -> QWidget:

        row = QWidget()

        row_layout = QHBoxLayout(
            row
        )

        row_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        label_widget = QLabel(
            label
        )

        label_widget.setStyleSheet(
            f"""
            color: {COLORS['text_dim']};
            font-size: 12px;
            """
        )

        row_layout.addWidget(
            label_widget
        )

        row_layout.addStretch()

        value_widget = QLabel(
            value
        )

        value_widget.setStyleSheet(
            """
            font-size: 12px;
            font-weight: 600;
            """
        )

        row_layout.addWidget(
            value_widget
        )

        return row

    def _clear_stats(self):

        while self.stats_layout.count():

            item = (
                self.stats_layout.takeAt(
                    0
                )
            )

            widget = item.widget()

            if widget:

                widget.deleteLater()

    def _render_stats(
        self,
        total,
        source_counts,
        category_counts,
        highest,
    ):

        self._clear_stats()

        if total is None:

            placeholder = QLabel(
                "Run a review to see "
                "results here."
            )

            placeholder.setStyleSheet(
                f"""
                color: {COLORS['text_dim']};
                font-size: 12px;
                """
            )

            placeholder.setWordWrap(
                True
            )

            self.stats_layout.addWidget(
                placeholder
            )

            return

        self.stats_layout.addWidget(
            self._stat_row(
                "Total findings",
                str(total),
            )
        )

        if highest:

            _, fg, _, _ = severity_style(
                highest
            )

            row = QWidget()

            row_layout = QHBoxLayout(
                row
            )

            row_layout.setContentsMargins(
                0,
                0,
                0,
                0,
            )

            label = QLabel(
                "Highest severity"
            )

            label.setStyleSheet(
                f"""
                color: {COLORS['text_dim']};
                font-size: 12px;
                """
            )

            row_layout.addWidget(
                label
            )

            row_layout.addStretch()

            severity_label = QLabel(
                str(highest).upper()
            )

            severity_label.setStyleSheet(
                f"""
                color: {fg};
                font-size: 12px;
                font-weight: 700;
                """
            )

            row_layout.addWidget(
                severity_label
            )

            self.stats_layout.addWidget(
                row
            )

        else:

            self.stats_layout.addWidget(
                self._stat_row(
                    "Highest severity",
                    "-",
                )
            )

        correlated = source_counts.get(
            "correlated",
            0,
        )

        ai_only = source_counts.get(
            "ai_only",
            0,
        )

        semgrep_only = source_counts.get(
            "semgrep_only",
            0,
        )

        if total > 0:

            self.stats_layout.addWidget(
                self._stat_row(
                    "AI + Semgrep",
                    str(correlated),
                )
            )

            self.stats_layout.addWidget(
                self._stat_row(
                    "AI only",
                    str(ai_only),
                )
            )

            self.stats_layout.addWidget(
                self._stat_row(
                    "Semgrep only",
                    str(semgrep_only),
                )
            )

        if category_counts:

            divider = QFrame()

            divider.setFrameShape(
                QFrame.HLine
            )

            divider.setStyleSheet(
                f"""
                color: {COLORS['border']};
                """
            )

            self.stats_layout.addWidget(
                divider
            )

            category_header = QLabel(
                "BY CATEGORY"
            )

            category_header.setObjectName(
                "sectionLabel"
            )

            self.stats_layout.addWidget(
                category_header
            )

            for category, count in sorted(
                category_counts.items()
            ):

                self.stats_layout.addWidget(
                    self._stat_row(
                        str(category),
                        str(count),
                    )
                )

    def show_pending(self):

        self._replace_decision_badge(
            "REVIEWING...",
            COLORS["panel_alt"],
            COLORS["accent"],
            COLORS["accent_dim"],
        )

        self._render_stats(
            total=None,
            source_counts={},
            category_counts={},
            highest=None,
        )

    def show_error(self):

        self._replace_decision_badge(
            "REVIEW FAILED",
            "#3d1a17",
            "#ff8a65",
            "#6b2e28",
        )

        self._render_stats(
            total=None,
            source_counts={},
            category_counts={},
            highest=None,
        )

    def update_from_result(
        self,
        result: dict,
    ):

        findings = (
            result.get("findings")
            or []
        )

        policy = (
            result.get("policy")
            or {}
        )

        decision = (
            policy.get("decision")
            or "UNKNOWN"
        ).upper()

        highest = (
            policy.get(
                "highest_severity"
            )
        )

        decision_colors = {
            "PASS": (
                "#12331f",
                COLORS["good"],
                "#1f5c3a",
            ),
            "FAIL": (
                "#3d1a17",
                "#ff8a65",
                "#6b2e28",
            ),
        }

        bg, fg, border = (
            decision_colors.get(
                decision,
                (
                    "#12283d",
                    COLORS["accent"],
                    "#20456b",
                ),
            )
        )

        self._replace_decision_badge(
            f"● {decision.replace('_', ' ')}",
            bg,
            fg,
            border,
        )

        source_counts = {
            "correlated": 0,
            "ai_only": 0,
            "semgrep_only": 0,
        }

        category_counts = {}

        for finding in findings:

            sources = normalize_sources(
                finding.get("source")
            )

            normalized_sources = {
                source.lower()
                for source in sources
            }

            if (
                "ai" in normalized_sources
                and "semgrep" in normalized_sources
            ):

                source_counts[
                    "correlated"
                ] += 1

            elif normalized_sources == {
                "ai"
            }:

                source_counts[
                    "ai_only"
                ] += 1

            elif normalized_sources == {
                "semgrep"
            }:

                source_counts[
                    "semgrep_only"
                ] += 1

            category = (
                finding.get("category")
                or "uncategorized"
            )

            category_counts[
                category
            ] = (
                category_counts.get(
                    category,
                    0,
                )
                + 1
            )

        self._render_stats(
            total=len(findings),
            source_counts=source_counts,
            category_counts=category_counts,
            highest=highest,
        )


# ==========================================================
# Background worker
# ==========================================================

class ReviewWorker(QObject):

    finished = Signal(dict)
    error = Signal(str)

    def __init__(
        self,
        code: str,
        language: str,
    ):

        super().__init__()

        self.code = code
        self.language = language

    @Slot()
    def run(self):

        try:

            result = analyze_code(
                code=self.code,
                language=self.language,
            )

            if not isinstance(result, dict):

                raise TypeError(
                    "analyze_code() must return a dictionary."
                )

            self.finished.emit(
                result
            )

        except Exception as error:

            self.error.emit(
                f"{type(error).__name__}: {error}"
            )


# ==========================================================
# Main window
# ==========================================================

class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.setWindowTitle(
            "AI DevSecOps Code Reviewer"
        )

        self.resize(
            1200,
            780,
        )

        self.setMinimumSize(
            900,
            620,
        )

        self.review_thread = None
        self.review_worker = None

        central_widget = QWidget()

        self.setCentralWidget(
            central_widget
        )

        root_layout = QVBoxLayout(
            central_widget
        )

        root_layout.setContentsMargins(
            20,
            16,
            20,
            16,
        )

        root_layout.setSpacing(
            16
        )

        root_layout.addWidget(
            self._build_header()
        )

        root_layout.addWidget(
            self._build_editor_row(),
            stretch=1,
        )

        root_layout.addLayout(
            self._build_controls_row()
        )

        root_layout.addWidget(
            self._build_findings_section(),
            stretch=1,
        )

        QShortcut(
            QKeySequence("Ctrl+Return"),
            self,
            activated=self.review_code,
        )

        QShortcut(
            QKeySequence("Ctrl+Enter"),
            self,
            activated=self.review_code,
        )

    # ------------------------------------------------------
    # Header
    # ------------------------------------------------------

    def _build_header(self):

        header = QWidget()

        layout = QHBoxLayout(
            header
        )

        layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        title_box = QVBoxLayout()

        title = QLabel(
            "🛡 AI DevSecOps Code Reviewer"
        )

        title.setObjectName(
            "appTitle"
        )

        subtitle = QLabel(
            "Analyze • Detect • Correlate"
        )

        subtitle.setObjectName(
            "appSubtitle"
        )

        title_box.addWidget(
            title
        )

        title_box.addWidget(
            subtitle
        )

        layout.addLayout(
            title_box
        )

        layout.addStretch()

        status_row = QHBoxLayout()

        status_row.addWidget(
            make_status_dot(
                COLORS["good"]
            )
        )

        status_label = QLabel(
            "Local AI"
        )

        status_label.setStyleSheet(
            f"""
            color: {COLORS['text_dim']};
            font-size: 12px;
            """
        )

        status_row.addWidget(
            status_label
        )

        layout.addLayout(
            status_row
        )

        return header

    # ------------------------------------------------------
    # Editor
    # ------------------------------------------------------

    def _build_editor_row(self):

        row = QWidget()

        layout = QHBoxLayout(
            row
        )

        layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        layout.setSpacing(
            16
        )

        code_panel = QFrame()

        code_panel.setObjectName(
            "panel"
        )

        code_layout = QVBoxLayout(
            code_panel
        )

        code_layout.setContentsMargins(
            16,
            14,
            16,
            14,
        )

        code_layout.setSpacing(
            8
        )

        code_header = QHBoxLayout()

        code_label = QLabel(
            "CODE"
        )

        code_label.setObjectName(
            "sectionLabel"
        )

        code_header.addWidget(
            code_label
        )

        code_header.addStretch()

        self.line_count_label = QLabel(
            "0 lines"
        )

        self.line_count_label.setStyleSheet(
            f"""
            color: {COLORS['text_dim']};
            font-size: 11px;
            """
        )

        code_header.addWidget(
            self.line_count_label
        )

        code_layout.addLayout(
            code_header
        )

        self.code_editor = CodeEditor()

        self.code_editor.textChanged.connect(
            self._update_line_count
        )

        code_layout.addWidget(
            self.code_editor,
            stretch=1,
        )

        layout.addWidget(
            code_panel,
            stretch=2,
        )

        self.overview_panel = (
            OverviewPanel()
        )

        layout.addWidget(
            self.overview_panel,
            stretch=1,
        )

        return row

    # ------------------------------------------------------
    # Controls
    # ------------------------------------------------------

    def _build_controls_row(self):

        layout = QHBoxLayout()

        layout.setSpacing(
            10
        )

        language_label = QLabel(
            "Language:"
        )

        language_label.setStyleSheet(
            f"""
            color: {COLORS['text_dim']};
            """
        )

        layout.addWidget(
            language_label
        )

        self.language_selector = (
            QComboBox()
        )

        self.language_selector.addItems(
            ["Python"]
        )

        self.language_selector.setFixedWidth(
            140
        )

        layout.addWidget(
            self.language_selector
        )

        layout.addStretch()

        self.clear_button = QPushButton(
            "Clear"
        )

        self.clear_button.setObjectName(
            "secondaryButton"
        )

        self.clear_button.setCursor(
            Qt.PointingHandCursor
        )

        self.clear_button.clicked.connect(
            self._clear_code
        )

        layout.addWidget(
            self.clear_button
        )

        self.progress_bar = QProgressBar()

        self.progress_bar.setRange(
            0,
            0,
        )

        self.progress_bar.setFixedWidth(
            120
        )

        self.progress_bar.setVisible(
            False
        )

        layout.addWidget(
            self.progress_bar
        )

        self.review_button = QPushButton(
            "⚡ Review Code"
        )

        self.review_button.setObjectName(
            "reviewButton"
        )

        self.review_button.setCursor(
            Qt.PointingHandCursor
        )

        self.review_button.clicked.connect(
            self.review_code
        )

        layout.addWidget(
            self.review_button
        )

        return layout

    # ------------------------------------------------------
    # Findings
    # ------------------------------------------------------

    def _build_findings_section(self):

        section = QWidget()

        layout = QVBoxLayout(
            section
        )

        layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        layout.setSpacing(
            8
        )

        header = QLabel(
            "FINDINGS"
        )

        header.setObjectName(
            "sectionLabel"
        )

        layout.addWidget(
            header
        )

        self.findings_scroll_area = (
            QScrollArea()
        )

        self.findings_scroll_area.setWidgetResizable(
            True
        )

        self.findings_container = (
            QWidget()
        )

        self.findings_layout = (
            QVBoxLayout(
                self.findings_container
            )
        )

        self.findings_layout.setContentsMargins(
            0,
            0,
            4,
            0,
        )

        self.findings_layout.setSpacing(
            10
        )

        self.findings_scroll_area.setWidget(
            self.findings_container
        )

        layout.addWidget(
            self.findings_scroll_area,
            stretch=1,
        )

        self._show_findings_placeholder(
            "Run a review to see findings here."
        )

        return section

    # ------------------------------------------------------
    # Helpers
    # ------------------------------------------------------

    def _update_line_count(self):

        line_count = (
            self.code_editor.blockCount()
        )

        self.line_count_label.setText(
            f"{line_count} line"
            f"{'s' if line_count != 1 else ''}"
        )

    def _clear_code(self):

        self.code_editor.clear()

        self._show_findings_placeholder(
            "Run a review to see findings here."
        )

        self.overview_panel._render_stats(
            total=None,
            source_counts={},
            category_counts={},
            highest=None,
        )

        self.overview_panel._replace_decision_badge(
            "NOT YET RUN",
            COLORS["panel_alt"],
            COLORS["text_dim"],
            COLORS["border"],
        )

    def _clear_findings_layout(self):

        while self.findings_layout.count():

            item = (
                self.findings_layout.takeAt(
                    0
                )
            )

            widget = item.widget()

            if widget:

                widget.deleteLater()

    def _show_findings_placeholder(
        self,
        message: str,
    ):

        self._clear_findings_layout()

        placeholder = QLabel(
            message
        )

        placeholder.setStyleSheet(
            f"""
            color: {COLORS['text_dim']};
            font-size: 12px;
            """
        )

        placeholder.setAlignment(
            Qt.AlignCenter
        )

        placeholder.setWordWrap(
            True
        )

        self.findings_layout.addWidget(
            placeholder
        )

        self.findings_layout.addStretch()

    # ------------------------------------------------------
    # Review
    # ------------------------------------------------------

    def review_code(self):

        if self.review_thread is not None:
            return

        code = (
            self.code_editor
            .toPlainText()
        )

        language = (
            self.language_selector
            .currentText()
            .lower()
        )

        if not code.strip():

            self._show_findings_placeholder(
                "Please paste some code before reviewing."
            )

            return

        self.review_button.setEnabled(
            False
        )

        self.clear_button.setEnabled(
            False
        )

        self.language_selector.setEnabled(
            False
        )

        self.progress_bar.setVisible(
            True
        )

        self.overview_panel.show_pending()

        self._show_findings_placeholder(
            "Reviewing code... "
            "AI and Semgrep are running."
        )

        thread = QThread(
            self
        )

        worker = ReviewWorker(
            code=code,
            language=language,
        )

        self.review_thread = thread
        self.review_worker = worker

        worker.moveToThread(
            thread
        )

        thread.started.connect(
            worker.run
        )

        worker.finished.connect(
            self.review_finished
        )

        worker.error.connect(
            self.review_error
        )

        worker.finished.connect(
            thread.quit
        )

        worker.error.connect(
            thread.quit
        )

        thread.finished.connect(
            worker.deleteLater
        )

        thread.finished.connect(
            self._review_thread_finished
        )

        thread.start()

    @Slot(dict)
    def review_finished(
        self,
        result: dict,
    ):

        self.overview_panel.update_from_result(
            result
        )

        findings = (
            result.get("findings")
            or []
        )

        self._clear_findings_layout()

        if not findings:

            self.findings_layout.addWidget(
                build_empty_state_card()
            )

        else:

            for finding in findings:

                if not isinstance(
                    finding,
                    dict,
                ):

                    continue

                self.findings_layout.addWidget(
                    FindingCard(
                        finding
                    )
                )

        self.findings_layout.addStretch()

        self._finish_review_ui()

    @Slot(str)
    def review_error(
        self,
        message: str,
    ):

        self.overview_panel.show_error()

        self._clear_findings_layout()

        self.findings_layout.addWidget(
            build_error_card(
                message
            )
        )

        self.findings_layout.addStretch()

        self._finish_review_ui()

    def _finish_review_ui(self):

        self.review_button.setEnabled(
            True
        )

        self.clear_button.setEnabled(
            True
        )

        self.language_selector.setEnabled(
            True
        )

        self.progress_bar.setVisible(
            False
        )

    @Slot()
    def _review_thread_finished(self):

        self.review_worker = None

        thread = self.review_thread

        self.review_thread = None

        if thread is not None:

            thread.deleteLater()

    # ------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------

    def closeEvent(
        self,
        event,
    ):

        thread = self.review_thread

        if (
            thread is not None
            and thread.isRunning()
        ):

            # analyze_code() cannot currently be
            # cancelled. Wait until it finishes.
            thread.quit()

            thread.wait()

        event.accept()


# ==========================================================
# Application startup
# ==========================================================

def main():

    app = QApplication(
        sys.argv
    )

    app.setStyleSheet(
        build_stylesheet()
    )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":
    main()