package org.example.detectors;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.List;
import java.util.regex.Pattern;

//CommandInjectionDetector
public class CommandInjectionDetector {
    private static final Pattern DANGEROUS_CHARACTERS = Pattern.compile("[;&|]");

    public void detectCmd(CompilationUnit cu, PrintStream out) {
        PrintStream originalOut = System.out;
        System.setOut(out);
        out.println("Запуск анализа уязвимостей Command Injection для файла: " + cu.getStorage().get().getFileName());
        try {
            new MethodVisitor().visit(cu, null);
            new CatchClauseVisitor().visit(cu, null);
            new PrintStackTraceVisitor().visit(cu, null);
        } finally {
            System.setOut(originalOut);
        }
        out.println();
    }

    private static class MethodVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(MethodDeclaration n, Void arg) {
            super.visit(n, arg);
            List<Node> nodes = n.getChildNodes();
            for (Node node : nodes) {
                checkNode(node);
            }
        }

        private void checkNode(Node node) {
            if (node instanceof MethodCallExpr methodCall) {
                String methodName = methodCall.getNameAsString();
                int methodLine = methodCall.getBegin().get().line;

                for (Expression arg : methodCall.getArguments()) {
                    String argument = arg.toString();
                    switch (methodName) {
                        case "exec" -> {
                            if (argument.contains("command") || containsDangerousCharacters(argument)) {
                                System.out.println("Возможная уязвимость внедрения команд обнаружена в строке: "
                                        + methodLine + ". " + "\n"
                                        + "Метод " + methodCall.getName()
                                        + " содержит выполнение команды, которая может быть уязвимой.");
                            }
                        }
                        case "close" -> {}
                        default -> {
                            if (methodName.equals("getInputStream") || methodName.equals("getOutputStream")) {
                                System.out.println("Возможно, ресурс не закрывается в строке: " + methodLine + ". " + "\n"
                                        + "Метод " + methodName + " открывает ресурс, который должен быть закрыт после использования.");
                            }
                        }
                    }
                }
            }
            List<Node> nodes = node.getChildNodes();
            for (Node childNode : nodes) {
                checkNode(childNode);
            }
        }

        // Опасные символы для ввода
        private boolean containsDangerousCharacters(String input) {
            return DANGEROUS_CHARACTERS.matcher(input).find();
        }
    }

    private static class CatchClauseVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(CatchClause n, Void arg) {
            super.visit(n, arg);
            System.out.println("Обнаружена обработка исключений в строке: " + n.getBegin().get().line);
        }
    }
    private static class PrintStackTraceVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);
            if (n.getNameAsString().equals("printStackTrace")) {
                System.out.println("Обнаружена потенциальная уязвимость раскрытия информации в строке: " + n.getBegin().get().line);
            }
        }
    }
}



