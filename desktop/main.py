import sys

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QPushButton,
    QTextEdit,
)
from backend.analysis_service import analyze_code

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("AI DevSecOps Code Reviewer")
        self.resize(1000, 700)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main vertical layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Title
        title = QLabel("AI DevSecOps Code Reviewer")
        main_layout.addWidget(title)

        # Language selection row
        language_layout = QHBoxLayout()

        language_label = QLabel("Language:")

        self.language_selector = QComboBox()
        self.language_selector.addItems([
            "Python"
        ])

        language_layout.addWidget(language_label)
        language_layout.addWidget(self.language_selector)

        main_layout.addLayout(language_layout)

        # Code editor
        code_label = QLabel("Paste your code:")

        self.code_editor = QTextEdit()
        self.code_editor.setPlaceholderText(
            "Paste your code here..."
        )

        main_layout.addWidget(code_label)
        main_layout.addWidget(self.code_editor)

        # Review button
        self.review_button = QPushButton("Review Code")
        self.review_button.clicked.connect(self.review_code)
        main_layout.addWidget(self.review_button)

        # Results
        results_label = QLabel("Results:")

        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        self.results_box.setPlaceholderText(
            "Your review results will appear here..."
        )

        main_layout.addWidget(results_label)
        main_layout.addWidget(self.results_box)
        
    def review_code(self):
        code = self.code_editor.toPlainText()
        language = self.language_selector.currentText().lower()

        if not code.strip():
            self.results_box.setPlainText(
                "Please paste some code before reviewing."
            )
            return

        self.results_box.setPlainText(
            "Reviewing code... Please wait."
        )

        try:
            result = analyze_code(
                code=code,
                language=language
            )

            output = (
                f"Summary:\n{result['summary']}\n\n"
                f"Decision: {result['policy']['decision']}\n"
                f"Highest Severity: "
                f"{result['policy']['highest_severity']}\n\n"
                "Findings:\n"
            )

            if not result["findings"]:
                output += "\nNo issues found."

            else:
                for index, finding in enumerate(
                    result["findings"],
                    start=1
                ):
                    output += (
                        f"\n{index}. {finding['title']}\n"
                        f"Category: {finding['category']}\n"
                        f"Severity: {finding['severity']}\n"
                        f"Source: {', '.join(finding['source'])}\n"
                        f"Evidence: {finding['evidence']}\n"
                        f"Impact: {finding['impact']}\n"
                        f"Remediation: {finding['remediation']}\n"
                    )

            self.results_box.setPlainText(output)

        except Exception as error:
            self.results_box.setPlainText(
                f"Error during review:\n{error}"
            )


app = QApplication(sys.argv)

window = MainWindow()
window.show()

sys.exit(app.exec())