package org.example.detectors;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.io.PrintStream;
import java.util.List;
import java.util.stream.Collectors;

public class XxeDetector {
    public void detectXxe(CompilationUnit cu, PrintStream out) {
        out.println("Запуск анализа уязвимостей XXE для файла: " + cu.getStorage().get().getFileName());
        List<Node> nodes = cu.getChildNodes();
        for (Node node : nodes) {
            if (node instanceof MethodDeclaration) {
                MethodDeclaration method = (MethodDeclaration) node;
                analyzeMethod(method, out);
            } else {
                detectXxe(node, out);
            }
        }
        out.println();
    }
    // почему то не выполняется строка переде третьим вызовом
    private void analyzeMethod(MethodDeclaration method, PrintStream out) {
        boolean isVulnerable = true;

        for (MethodCallExpr methodCall : method.findAll(MethodCallExpr.class)) {
            int methodLine = methodCall.getBegin().get().line;
            if (methodCall.getNameAsString().equals("setFeature")) {
                List<Node> args = methodCall.getArguments().stream().collect(Collectors.toList());
                if (args.size() == 2 && args.get(0) instanceof StringLiteralExpr) {
                    StringLiteralExpr arg1 = (StringLiteralExpr) args.get(0);
                    if (arg1.getValue().equals("http://apache.org/xml/features/disallow-doctype-decl") || arg1.getValue().equals("http://xml.org/sax/features/external-general-entities")) {
                            isVulnerable = false;
                            out.println("Возможная уязвимость XXE обнаружена в методе1: " + method.getNameAsString() + ". Проверьте аргументы" + ". В строке:" + methodLine);
                    }
                }
            }
            if (methodCall.getNameAsString().equals("newInstance")) {
                out.println("Отключите доступ к внешним объектам в методе: " + method.getNameAsString() + "В строке: " + methodLine);
            }


        }

        if (isVulnerable) {
            out.println("Возможная уязвимость XXE обнаружена в методе: " + method.getNameAsString() + " Проверьте аргументы.");
        }
    }

    private void detectXxe(Node node, PrintStream out) {
        List<Node> nodes = node.getChildNodes();
        for (Node childNode : nodes) {
            if (childNode instanceof MethodDeclaration) {
                MethodDeclaration method = (MethodDeclaration) childNode;
                analyzeMethod(method, out);
            } else {
                detectXxe(childNode, out);
            }
        }
    }
}




