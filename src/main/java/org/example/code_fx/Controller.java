package org.example.code_fx;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import javafx.application.Platform;
import javafx.scene.control.Label;
import javafx.stage.FileChooser;
import org.example.detectors.*;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Controller {

    @FXML
    private MenuItem menuSelectDirectory;

    @FXML
    private MenuItem menuExit;

    @FXML
    private Button button1;

    @FXML
    private Button exportButton;

    @FXML
    private TextArea textArea;

    @FXML
    private Label directoryPathLabel;

    private File selectedDirectory;

    @FXML
    private void initialize() {
        menuSelectDirectory.setOnAction(event -> handleSelectDirectory());
        menuExit.setOnAction(event -> handleExit());
        button1.setOnAction(event -> handleAnalyze());
        exportButton.setOnAction(event -> exportText());
    }

    private void handleSelectDirectory() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выбор директории");
        Stage stage = (Stage) textArea.getScene().getWindow();
        selectedDirectory = directoryChooser.showDialog(stage);
        if (selectedDirectory != null) {
            directoryPathLabel.setText("Выбранная директория: " + selectedDirectory.getAbsolutePath());
        }
    }

    private void exportText() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Сохранить файл");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Text Files", "*.txt"),
                new FileChooser.ExtensionFilter("All Files", "*.*"));

        // Получаем текущее окно (Stage)
        Stage stage = (Stage) textArea.getScene().getWindow();
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            saveTextToFile(textArea.getText(), file);
        }
    }

    private void saveTextToFile(String content, File file) {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleExit() {
        Stage stage = (Stage) textArea.getScene().getWindow();
        stage.close();
    }

    private void handleAnalyze() {
        if (selectedDirectory == null) {
            textArea.setText("Сначала выберите директорию.");
            return;
        }

        new Thread(() -> {
            ByteArrayOutputStream idorOutputStream = new ByteArrayOutputStream();
            PrintStream idorPrintStream = new PrintStream(idorOutputStream);

            ByteArrayOutputStream xssOutputStream = new ByteArrayOutputStream();
            PrintStream xssPrintStream = new PrintStream(xssOutputStream);

            ByteArrayOutputStream xxeOutputStream = new ByteArrayOutputStream();
            PrintStream xxePrintStream = new PrintStream(xxeOutputStream);

            ByteArrayOutputStream sqlOutputStream = new ByteArrayOutputStream();
            PrintStream sqlPrintStream = new PrintStream(sqlOutputStream);

            ByteArrayOutputStream rmiOutputStream = new ByteArrayOutputStream();
            PrintStream rmiPrintStream = new PrintStream(rmiOutputStream);

            ByteArrayOutputStream cmdOutputStream = new ByteArrayOutputStream();
            PrintStream cmdPrintStream = new PrintStream(cmdOutputStream);

//            ByteArrayOutputStream conOutputStream = new ByteArrayOutputStream();
//            PrintStream conPrintStream = new PrintStream(conOutputStream);

            IdorDetector idorDetector = new IdorDetector();
            XssDetector xssDetector = new XssDetector();
            XxeDetector xxeDetector = new XxeDetector();
            SqlInjectionDetector sqlInjectionDetector = new SqlInjectionDetector();
            RmiDetector rmiDetector = new RmiDetector();
            CommandInjectionDetector cmdDetector = new CommandInjectionDetector();
//            DatabaseConnectionDetector conDetector = new DatabaseConnectionDetector();

            try (Stream<Path> paths = Files.walk(Paths.get(selectedDirectory.toURI()))) {
                List<File> javaFiles = paths.filter(Files::isRegularFile)
                        .filter(path -> path.toString().endsWith(".java"))
                        .map(Path::toFile)
                        .collect(Collectors.toList());

                JavaParser parser = new JavaParser();

                // Группа для IDOR
                idorPrintStream.println("====== IDOR ======");
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
                        if (compilationUnit != null) {
                            idorDetector.detectIdor(compilationUnit, idorPrintStream);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        idorPrintStream.println("Не удалось проанализировать файл: " + javaFile.getAbsolutePath());
                    }
                }
                idorPrintStream.println();

                // Группа для XSS
                xssPrintStream.println("====== XSS ======");
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
                        if (compilationUnit != null) {
                            xssDetector.analyze(compilationUnit, xssPrintStream);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        xssPrintStream.println("Не удалось проанализировать файл: " + javaFile.getAbsolutePath());
                    }
                }
                xssPrintStream.println();

                // Группа для XXE
                xxePrintStream.println("====== XXE ======");
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
                        if (compilationUnit != null) {
                            xxeDetector.detectXxe(compilationUnit, xxePrintStream);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        xxePrintStream.println("Не удалось проанализировать файл: " + javaFile.getAbsolutePath());
                    }
                }
                xxePrintStream.println();

                // Группа для Sql
                sqlPrintStream.println("====== SQl ======");
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
                        if (compilationUnit != null) {
                            sqlInjectionDetector.detectSql(compilationUnit, sqlPrintStream);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        sqlPrintStream.println("Не удалось проанализировать файл: " + javaFile.getAbsolutePath());
                    }
                }
                sqlPrintStream.println();

                // Группа для RMI
                rmiPrintStream.println("====== RMI ======");
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
                        if (compilationUnit != null) {
                            rmiDetector.detectRmi(compilationUnit, rmiPrintStream);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        rmiPrintStream.println("Не удалось проанализировать файл: " + javaFile.getAbsolutePath());
                    }
                }
                rmiPrintStream.println();

                // Группа для CommandInjection
                cmdPrintStream.println("====== Cmd ======");
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
                        if (compilationUnit != null) {
                            cmdDetector.detectCmd(compilationUnit, cmdPrintStream);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        cmdPrintStream.println("Не удалось проанализировать файл: " + javaFile.getAbsolutePath());
                    }
                }
                cmdPrintStream.println();

//                // Группа для DatabaseConnection
//                conPrintStream.println("====== Connection Analysis ======");
//                for (File javaFile : javaFiles) {
//                    try {
//                        CompilationUnit compilationUnit = parser.parse(javaFile).getResult().orElse(null);
//                        if (compilationUnit != null) {
//                            conDetector.detectConnection(compilationUnit, conPrintStream);
//                        }
//                    } catch (IOException e) {
//                        e.printStackTrace();
//                        conPrintStream.println("Failed to parse file: " + javaFile.getAbsolutePath());
//                    }
//                }
//                conPrintStream.println();

            } catch (IOException e) {
                e.printStackTrace();
                idorPrintStream.println("Ошибка чтения директории: " + selectedDirectory.getAbsolutePath());
                xssPrintStream.println("Ошибка чтения директории: " + selectedDirectory.getAbsolutePath());
                xxePrintStream.println("Ошибка чтения директории: " + selectedDirectory.getAbsolutePath());
                sqlPrintStream.println("Ошибка чтения директории: " + selectedDirectory.getAbsolutePath());
                rmiPrintStream.println("Ошибка чтения директории: " + selectedDirectory.getAbsolutePath());
                cmdPrintStream.println("Ошибка чтения директории: " + selectedDirectory.getAbsolutePath());
//                conPrintStream.println("Failed to read directory: " + selectedDirectory.getAbsolutePath());
            }

            String resultText =
                    idorOutputStream.toString()
                    + xssOutputStream.toString()
                    + xxeOutputStream.toString()
                    + sqlOutputStream.toString()
                    + rmiOutputStream.toString()
                    + cmdOutputStream.toString();
//                    + conPrintStream.toString();
            Platform.runLater(() -> textArea.setText(resultText));
        }).start();
    }

}