package org.example.detectors;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.PrintStream;


public class XssDetector {

    public void analyze(CompilationUnit cu, PrintStream out) {
        PrintStream originalOut = System.out;
        System.setOut(out);
        out.println("Запуск анализа уязвимостей XSS для файла: " + cu.getStorage().get().getFileName());
        try {
            new MethodVisitor().visit(cu, null);
        } finally {
            System.setOut(originalOut);
        }
        out.println();
    }

    private static class MethodVisitor extends VoidVisitorAdapter<Void> {
        public void visit(MethodCallExpr n, Void arg) {
            if (n.getNameAsString().equals("getParameter")) {
                if (n.getArgument(0).isStringLiteralExpr()) {
                    System.out.println("Потенциальная XSS уязвимость в строке: " + n.getBegin().get().line + ". Проверьте метод: " + n.getNameAsString() + ".");
                }else if (n.getArgument(0).isBinaryExpr()) {
                    System.out.println("Обнаружена XSS уязвимость в строке: " + n.getBegin().get().line + ". Проверьте метод: " + n.getNameAsString() + ".");
                    printVariables(n.getArgument(0));
                }
            }else if (n.getNameAsString().equals("write")
                    || n.getNameAsString().equals("println")
                    || n.getNameAsString().equals("writeln")
                    || n.getNameAsString().equals("innerHTML")
                    || n.getNameAsString().equals("outerHTML")) {
                if (n.getArgument(0).isStringLiteralExpr()) {
                    System.out.println("Потенциальная XSS уязвимость в строке: " + n.getBegin().get().line);
                } else if (n.getArgument(0).isBinaryExpr()) {
                    System.out.println("Обнаружена XSS уязвимость в строке: " + n.getBegin().get().line + ". Проверьте метод: " + n.getNameAsString() + ".");
                    printVariables(n.getArgument(0));
                }
            }
            super.visit(n, arg);
        }

        private void printVariables(Expression expr) {
            if (expr.isBinaryExpr()) {
                BinaryExpr binaryExpr = expr.asBinaryExpr();
                if (binaryExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                    printVariables(binaryExpr.getLeft());
                    printVariables(binaryExpr.getRight());
                }
            } else if (expr.isNameExpr()) {
                System.out.println( "Уязвимые переменные: " + expr.asNameExpr().getName());
            }
        }
    }
}
