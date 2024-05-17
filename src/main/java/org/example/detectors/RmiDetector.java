package org.example.detectors;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.PrintStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

//ServerConnection
public class RmiDetector {
    public void detectRmi(CompilationUnit cu, PrintStream out) {
        PrintStream originalOut = System.out;
        System.setOut(out);
        out.println("Запуск анализа уязвимостей RMI для файла: " + cu.getStorage().get().getFileName());
        try {
            new RmiCallChecker().visit(cu, null);
            new ClassVisitor().visit(cu, null);
        } finally {
            System.setOut(originalOut);
        }
        out.println();
    }

    private static class ClassVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(ClassOrInterfaceDeclaration n, Void arg) {
            super.visit(n, arg);

            boolean hasRmiCalls = n.getMethods().stream().anyMatch(this::hasRmiCalls);
            if (hasRmiCalls) {
                boolean hasRmiAuth = n.isAnnotationPresent("RmiAuthentication");
                boolean hasRmiSecurity = n.isAnnotationPresent("RmiSecurityManager");

                if (!hasRmiAuth) {
                    System.out.println("Класс " + n.getName() + " не имеет аннотации @RmiAuthentication.");
                }

                if (!hasRmiSecurity) {
                    System.out.println("Класс " + n.getName() + " не имеет аннотации @RmiSecurityManager.");
                }

                n.getMethods().forEach(method -> {
                    new MethodVisitorRebind().visit(method, null);
                    if (hasRmiCalls(method)) {
                        checkMethodAnnotations(method);
                    }
                });
            }
        }

        private boolean hasRmiCalls(MethodDeclaration method) {
            RmiCallChecker rmiCallChecker = new RmiCallChecker();
            rmiCallChecker.visit(method, null);
            return rmiCallChecker.hasRmiCalls();
        }

        private void checkMethodAnnotations(MethodDeclaration method) {
            boolean hasRmiAuth = method.isAnnotationPresent("RmiAuthentication");
            boolean hasRmiSecurity = method.isAnnotationPresent("RmiSecurityManager");

            if (!hasRmiAuth) {
                System.out.println("Метод " + method.getName() + " не имеет аннотации @RmiAuthentication.");
            }

            if (!hasRmiSecurity) {
                System.out.println("Метод " + method.getName() + " не имеет аннотации @RmiSecurityManager.");
            }
        }
    }

    private static class RmiCallChecker extends VoidVisitorAdapter<Void> {
        private boolean hasRmiCalls = false;

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);
            String methodName = n.getNameAsString();
            if (isRmiMethod(methodName)) {
                hasRmiCalls = true;
            }
        }

        private boolean isRmiMethod(String methodName) {
            return methodName.equals("rebind") ||
                    methodName.equals("bind") ||
                    methodName.equals("unbind") ||
                    methodName.equals("createRegistry") ||
                    methodName.equals("exportObject") ||
                    methodName.equals("getRegistry");
        }

        public boolean hasRmiCalls() {
            return hasRmiCalls;
        }
    }

    private static class MethodVisitorRebind extends VoidVisitorAdapter<Void> {
        private Set<Integer> reportedPorts = new HashSet<>();
        private Set<Node> reportedNodes = new HashSet<>();

        @Override
        public void visit(MethodDeclaration n, Void arg) {
            super.visit(n, arg);
            List<Node> nodes = n.getChildNodes();
            for (Node node : nodes) {
                checkPort(node);
                checkExceptionHandling(node);
                checkNode(node);
            }
        }

        private void checkNode(Node node) {
            if (node instanceof MethodCallExpr methodCall) {
                if (reportedNodes.add(methodCall)) {
                    String methodName = methodCall.getNameAsString();
                    int methodLine = methodCall.getBegin().get().line;
                    if (methodName.equals("rebind") || methodName.equals("bind") || methodName.equals("unbind")) {
                        System.out.println("Обнаружена потенциальная проблема безопасности RMI в строке: "
                                + methodLine + ". " + "\n"
                                + "Метод " + methodCall.getName()
                                + " содержит операцию RMI, которая может быть уязвимой.");
                    }
                }
            }
            node.getChildNodes().forEach(this::checkNode);
        }

        private void checkExceptionHandling(Node node) {
            if (node instanceof CatchClause) {
                CatchClause catchClause = (CatchClause) node;
                System.out.println("Обнаружена обработка исключений в строке: "
                        + catchClause.getBegin().get().line + ". Используйте логирование." );
            }
            node.getChildNodes().forEach(this::checkNode);
        }

        private void checkPort(Node node) {
            if (node instanceof MethodCallExpr methodCall) {
                NodeList<Expression> arguments = methodCall.getArguments();
                for (Expression argument : arguments) {
                    if (argument instanceof IntegerLiteralExpr) {
                        IntegerLiteralExpr integerLiteral = (IntegerLiteralExpr) argument;
                        String methodName = methodCall.getNameAsString();
                        if (isPortMethod(methodName) && reportedPorts.add(integerLiteral.asInt())) {
                            System.out.println("Используется порт: " + integerLiteral.asInt() + " в строке: " + integerLiteral.getBegin().get().line);
                        }
                    }
                }
            }
            node.getChildNodes().forEach(this::checkPort);
        }

        private boolean isPortMethod(String methodName) {
            return methodName.equals("createRegistry") ||
                    methodName.equals("exportObject") ||
                    methodName.equals("getRegistry");
        }


    }
}
