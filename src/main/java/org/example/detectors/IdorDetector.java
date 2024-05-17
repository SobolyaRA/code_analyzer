package org.example.detectors;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.PrintStream;

public class IdorDetector {
    public void detectIdor(CompilationUnit cu, PrintStream out) {
        PrintStream originalOut = System.out;
        System.setOut(out);
        out.println("Запуск анализа уязвимостей IDOR для файла: " + cu.getStorage().get().getFileName());
        try {
            new MethodVisitor().visit(cu, null);
        } finally {
            System.setOut(originalOut);
        }
        out.println();
    }

    private static class MethodVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(MethodDeclaration n, Void arg) {
            if (
                    n.getAnnotationByName("RequestMapping").isPresent()
                    || n.getAnnotationByName("GetMapping").isPresent()
                    || n.getAnnotationByName("PostMapping").isPresent()
                    || n.getAnnotationByName("PutMapping").isPresent()
                    || n.getAnnotationByName("DeleteMapping").isPresent()
            ) {
                for (Parameter parameter : n.getParameters()) {
                    if (
                            parameter
                                    .getAnnotationByName("PathVariable")
                                    .isPresent()
                    ) {
                        // Проверка наличия механизмов аутентификации и авторизации
                        if (
                                !n.getAnnotationByName("PreAuthorize").isPresent()
                                && !n.getAnnotationByName("PostAuthorize").isPresent()
                                && !n.getAnnotationByName("Secured").isPresent()
                        ) {
                            System.out.println(
                                    "Возможная уязвимость IDOR обнаружена в методе: "
                                            + n.getName());
                            System.out.println("Проверьте наличие механизмов аутентификации.");
                        }
                    }
                }
            }
            super.visit(n, arg);
        }
    }
}

