package org.example.detectors;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.PrintStream;
import java.util.HashSet;
import java.util.Set;

public class SqlInjectionDetector {

    public void detectSql(CompilationUnit cu, PrintStream out) {
        PrintStream originalOut = System.out;
        System.setOut(out);
        out.println("Запуск анализа уязвимостей SqlInjection для файла: " + cu.getStorage().get().getFileName());
        try {
            new MethodVisitor().visit(cu, null);
        } finally {
            System.setOut(originalOut);
        }
        out.println();
    }

    private static class MethodVisitor extends VoidVisitorAdapter<Void> {
        private Set<String> untrustedVariables = new HashSet<>();

        public void visit(MethodCallExpr n, Void arg) {
            if (n.getNameAsString().equals("getParameter")) {
                if (n.getArgument(0).isStringLiteralExpr()) {
                    String paramName = n.getArgument(0).asStringLiteralExpr().asString();
                    untrustedVariables.add(paramName);
                    System.out.println("Потенциальная SQL Injection в строке: " + n.getBegin().get().line + ". Проверьте метод: " + n.getNameAsString() + ".");
                }
            } else if (n.getNameAsString().equals("executeQuery")) {
                if (n.getArguments().isEmpty()) {
                    return;
                }
                Expression arg0 = n.getArgument(0);
                printPotentialSQLInjection(arg0, n.getNameAsString(), n.getBegin().get().line);
            }
            super.visit(n, arg);
        }

        private void printPotentialSQLInjection(Expression expr, String methodName, int line) {
            if (expr.isBinaryExpr()) {
                BinaryExpr binaryExpr = expr.asBinaryExpr();
                if (binaryExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                    printPotentialSQLInjection(binaryExpr.getLeft(), methodName, line);
                    printPotentialSQLInjection(binaryExpr.getRight(), methodName, line);
                }
            } else if (expr.isNameExpr()) {
                String varName = expr.asNameExpr().getNameAsString();
                if (untrustedVariables.contains(varName)) {
                    System.out.println("Обнаружена SQL Injection в строке: " + line + ". Проверьте метод: " + methodName + ".");
                    System.out.println("Уязвимые переменные: " + varName);
                }
            } else if (expr.isMethodCallExpr()) {
                MethodCallExpr methodCallExpr = expr.asMethodCallExpr();
                for (Expression arg : methodCallExpr.getArguments()) {
                    printPotentialSQLInjection(arg, methodName, line);
                }
            } else if (expr.isFieldAccessExpr()) {
                FieldAccessExpr fieldAccessExpr = expr.asFieldAccessExpr();
                String fieldName = fieldAccessExpr.getNameAsString();
                if (untrustedVariables.contains(fieldName)) {
                    System.out.println("Обнаружена SQL Injection в строке: " + line + ". Проверьте метод: " + methodName + ".");
                    System.out.println("Уязвимые переменные: " + fieldName);
                }
            }
        }

    }
}
