package org.example.parser;

import com.github.javaparser.JavaParser;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;

public class ParserCode {

    public CompilationUnit parse(String filePath) {
        try {
            return StaticJavaParser.parse(Paths.get(filePath));
        } catch (IOException e) {
            throw new RuntimeException("Ошибка при парсинге файла " + filePath, e);
        }
    }
}

