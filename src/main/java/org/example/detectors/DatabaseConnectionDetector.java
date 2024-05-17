package org.example.detectors;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithArguments;
import com.github.javaparser.ast.nodeTypes.NodeWithVariables;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.List;

//DatabaseConnection
public class DatabaseConnectionDetector {
    public void detectConnection(CompilationUnit cu, PrintStream out) {
        PrintStream originalOut = System.out;
        System.setOut(out);
        out.println("Starting Connection analysis for file: " + cu.getStorage().get().getFileName());
        try {
//            new UserInputVisitor().visit(cu, null);
            new MethodVisitorDB().visit(cu, null);
        } finally {
            System.setOut(originalOut);
        }
        out.println();
    }

    private static class UserInputVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(FieldDeclaration n, Void arg) {
            super.visit(n, arg);
            for (VariableDeclarator var : n.getVariables()) {
                String varName = var.getNameAsString();
                int line = n.getBegin().get().line;
                if (varName.equals("user") || varName.equals("password")) {
                    System.out.println("Потенциальная проблема с небезопасным подключением к базе данных обнаружена в строке: "
                            + line + ". " + "\n"
                            + "Переменная " + varName
                            + " может содержать пользовательский ввод.");
                }
            }
        }
    }

    private static class MethodVisitorDB extends VoidVisitorAdapter<Void> {
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
                    if (methodName.equals("getConnection")) {
                        if (argument.contains("user")) {
                            System.out.println("Потенциальная проблема с небезопасным подключением к базе данных обнаружена в строке: "
                                    + methodLine + ". " + "\n"
                                    + "Метод " + methodName
                                    + " содержит переменную " + argument + ", которая может содержать пользовательский ввод.");
                        } else if (argument.contains("password")) {
                            System.out.println("Потенциальная проблема с небезопасным подключением к базе данных обнаружена в строке: "
                                    + methodLine + ". " + "\n"
                                    + "Метод " + methodName
                                    + " содержит переменную " + argument + ", которая может содержать пользовательский ввод.");
                        }
                    }
                }
            }
            List<Node> nodes = node.getChildNodes();
            for (Node childNode : nodes) {
                checkNode(childNode);
            }
        }
    }
}
