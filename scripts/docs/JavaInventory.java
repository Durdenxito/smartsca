import com.sun.source.tree.*;
import com.sun.source.util.JavacTask;
import java.nio.file.*;
import java.util.*;
import javax.tools.*;
import javax.xml.stream.*;

/** Extracts declarations with the JDK parser, without requiring application dependencies. */
public class JavaInventory {
    static XMLStreamWriter xml;

    static void element(String name, String... attributes) throws Exception {
        xml.writeStartElement(name);
        for (int i = 0; i < attributes.length; i += 2)
            xml.writeAttribute(attributes[i], attributes[i + 1]);
    }

    static void describe(ClassTree type, String pkg, String parent, List<String> imports) throws Exception {
        String simple = type.getSimpleName().toString();
        if (simple.isEmpty()) return;
        String name = parent.isEmpty() ? simple : parent + "." + simple;
        element("class", "name", name, "package", pkg, "kind", type.getKind().name());
        for (String imported : imports) { element("import", "name", imported); xml.writeEndElement(); }
        if (type.getExtendsClause() != null) {
            element("extends", "type", type.getExtendsClause().toString()); xml.writeEndElement();
        }
        for (Tree implemented : type.getImplementsClause()) {
            element("implements", "type", implemented.toString()); xml.writeEndElement();
        }
        for (Tree member : type.getMembers()) {
            if (member instanceof VariableTree field) {
                element("field", "name", field.getName().toString(), "type", String.valueOf(field.getType()),
                    "modifiers", field.getModifiers().getFlags().toString());
                xml.writeEndElement();
            } else if (member instanceof MethodTree method) {
                element("method", "name", method.getName().contentEquals("<init>") ? simple : method.getName().toString(),
                    "type", method.getReturnType() == null ? "" : method.getReturnType().toString(),
                    "modifiers", method.getModifiers().getFlags().toString());
                for (VariableTree parameter : method.getParameters()) {
                    element("parameter", "name", parameter.getName().toString(), "type", parameter.getType().toString());
                    xml.writeEndElement();
                }
                xml.writeEndElement();
            } else if (member instanceof ClassTree nested) describe(nested, pkg, name, imports);
        }
        xml.writeEndElement();
    }

    public static void main(String[] args) throws Exception {
        Path source = Path.of(args[0]);
        List<Path> files;
        try (var paths = Files.walk(source)) {
            files = paths.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("A full JDK is required");
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        try (var manager = compiler.getStandardFileManager(diagnostics, null, null)) {
            var task = (JavacTask) compiler.getTask(null, manager, diagnostics, List.of("-proc:none"), null,
                manager.getJavaFileObjectsFromPaths(files));
            var units = new ArrayList<CompilationUnitTree>();
            task.parse().forEach(units::add);
            for (var diagnostic : diagnostics.getDiagnostics())
                if (diagnostic.getKind() == Diagnostic.Kind.ERROR) throw new IllegalArgumentException(diagnostic.toString());
            Path output = Path.of(args[1]);
            Files.createDirectories(output.toAbsolutePath().getParent());
            try (var stream = Files.newOutputStream(output)) {
                xml = XMLOutputFactory.newFactory().createXMLStreamWriter(stream, "UTF-8");
                xml.writeStartDocument("UTF-8", "1.0"); element("inventory");
                for (var unit : units) {
                    String pkg = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
                    var imports = unit.getImports().stream().map(i -> i.getQualifiedIdentifier().toString()).toList();
                    for (var declaration : unit.getTypeDecls())
                        if (declaration instanceof ClassTree type) describe(type, pkg, "", imports);
                }
                xml.writeEndElement(); xml.writeEndDocument(); xml.close();
            }
        }
    }
}
