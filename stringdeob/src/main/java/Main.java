import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;

/*
Plan:
    - Replace every ldc_w + invoke_static with instead a const pool reference to the decrypted string.
    Need to figure out again how to modify const pool, but that's the basic approach.
 */

public class Main {
    // May not need a custom classloader if you just add the jar itself to the classpath;
    // then it should be found by the system loader.

    // Would be nice to add entire jar to the classpath, such that we can easily
    // locate the class we need?
    private static String getClassName(String classPath) {
        return classPath.substring(0, classPath.indexOf(".class")).replace("/", ".");
    }

    private static void outputJarEntries(JarFile jar) {
        jar.stream()
           .map(ZipEntry::getName)
           .forEach(System.out::println);
    }

    // Take an initial jar file, and swap out all classes that match the hashmap.
    private static void repackJar(JarFile jar, HashMap<String, byte[]> newClasses, String outFilename) throws IOException {
        JarOutputStream targetJar = new JarOutputStream(new FileOutputStream(outFilename), jar.getManifest());

        jar.stream()
           .forEach(jarEntry -> {
               try {

                   /*
                   if (newClasses.containsKey(jarEntry.getName())) {
                       JarEntry newEntry = new JarEntry(jarEntry.getName());
                       targetJar.putNextEntry(newEntry);
                       targetJar.write(newClasses.get(jarEntry.getName()));
                       targetJar.closeEntry();
                   } else {
                       targetJar.putNextEntry(jarEntry);
                       targetJar.closeEntry();
                   }
                   */

                   //targetJar.putNextEntry(jarEntry);
                   if (!jarEntry.isDirectory()) {
                       if (newClasses.containsKey(jarEntry.getName())) {
                           System.out.println("Writing custom class " + jarEntry.getName());
                           jarEntry.setSize(newClasses.get(jarEntry.getName()).length);
                           jarEntry.setMethod(ZipEntry.STORED);
                           jarEntry.setCompressedSize(jarEntry.getSize());
                           CRC32 crc = new CRC32();
                           //crc.update(newClasses.get(jarEntry.getName()));
                           crc.update(ByteBuffer.wrap(newClasses.get(jarEntry.getName())));
                           jarEntry.setCrc(crc.getValue());
                           targetJar.putNextEntry(jarEntry);
                           targetJar.write(newClasses.get(jarEntry.getName()));
                       } else {
                           System.out.println("Writing " + jarEntry.getName());
                           targetJar.putNextEntry(jarEntry);
                           targetJar.write(IOUtils.toByteArray(jar.getInputStream(jarEntry)));
                       }
                   } else {
                       targetJar.putNextEntry(jarEntry);
                   }
                   targetJar.closeEntry();
               } catch (IOException e) {
                   System.err.println(e.getMessage());
               }
           });
        targetJar.close();
    }

    public static void printDecryptedStrings() {
        JarFile jar;
        try {
            jar = new JarFile("jars/TRiBot-10.24.2.jar");
            HashMap<String, byte[]> obfClasses = new HashMap<>();

            jar.stream()
                    .filter(entry -> entry.getName().contains(".class"))
                    .forEach(entry -> {
                        try {
                            System.out.println("Adding obf class " + entry.getName());
                            obfClasses.put(entry.getName(), IOUtils.toByteArray(jar.getInputStream(entry)));
                        } catch (IOException e) {
                        }
                    });

            HashMap<String, byte[]> loaderClasses = new HashMap<>();
            obfClasses.keySet().forEach(className -> {
                loaderClasses.put(getClassName(className), obfClasses.get(className));
            });

            JarLoader loader = new JarLoader(loaderClasses);
            HashMap<String, Integer> encryptedRoutines = new HashMap<>();
            loaderClasses.keySet().stream()
                .map(clazz -> {
                    ClassReader reader = new ClassReader(loaderClasses.get(clazz));
                    CustomClassVisitor visitor = new CustomClassVisitor(clazz);
                    reader.accept(visitor, 0);

                    return visitor.encryptionRoutines;
                })
                .flatMap(Collection::stream)
                .forEach(routine -> encryptedRoutines.put(routine, 0));
                //.collect(Collectors.toCollection(LinkedList::new));


        removeEncryptedStrings(loaderClasses, loader, encryptedRoutines);
            /*
            try {
                Class pD = loader.findClass("obf.pD");
                // Delimiters @@ and !! are used
                String res = (String) pD.getDeclaredMethod("Ha", Object.class).invoke(null, "\\/");
                System.out.println(res);

            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
            */
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        // Next up: Repackaging the jar / supporting multiple transformations
        // Maybe we keep the original jar file, and just replace entries?
        // May be easiest to just recreate the dir structure

        /** Demo of decrypting strings
        printDecryptedStrings();
        System.exit(0);
        */

        // Need a method that simply inserts a println of the desired variable (Gb.class in this case)
        try {
            // Sha1
            //System.out.println(MessageDigest.getInstance("SHA").getDigestLength());
            //String pass = "584e";
            //String pass = "greentoad";
            String pass = "greentoad";
            byte[] data = FileUtils.readFileToByteArray(new File("501141-accounts.dat2"));
            MessageDigest message = MessageDigest.getInstance("SHA");
            message.update(pass.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secret = new SecretKeySpec(message.digest(), 0, 16, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret);
            System.out.println(cipher.getBlockSize());
            //cipher.update(data);
            byte[] finalData = cipher.doFinal(data);
            // Am I missing a step?

            pass = "584E07C4BGqO3alR9zSQtda3uChdbRZLNd";
            message = MessageDigest.getInstance("SHA");
            message.update(pass.getBytes(StandardCharsets.UTF_8));
            secret = new SecretKeySpec(message.digest(), 0, 16, "AES");
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret);
            finalData = cipher.doFinal(finalData);

            String out =  new String(finalData, StandardCharsets.UTF_8);
            System.out.println(finalData.length);
            System.out.println(out);
            System.out.println(out.length());
            FileUtils.writeByteArrayToFile(new File("/tmp/out.dump"), finalData);

            //System.out.println(Cipher.getInstance("AES"));
            //System.out.println(Cipher.DEC)
        } catch (Exception e) {
            System.err.println("Failed" + e.getMessage());

        }
        System.exit(0);

        //System.out.println(new File("jars/TRiBot-10.24.2.jar").exists());
        JarFile jar;
        try {
            jar = new JarFile("jars/TRiBot-10.24.2.jar");
            HashMap<String, byte[]> obfClasses = new HashMap<>();

            jar.stream()
               .filter(entry -> entry.getName().contains(".class"))
               .forEach(entry -> {
                   try {
                       System.out.println("Adding obf class " + entry.getName());
                       obfClasses.put(entry.getName(), IOUtils.toByteArray(jar.getInputStream(entry)));
                   } catch (IOException e) {}
               });

            HashMap<String, byte[]> loaderClasses = new HashMap<>();
            obfClasses.keySet().forEach(className -> {
                                   loaderClasses.put(getClassName(className), obfClasses.get(className));
                               });

            JarLoader loader = new JarLoader(loaderClasses);
            try {
                Class pD = loader.findClass("obf.pD");
                // Delimiters @@ and !! are used
                String res = (String)pD.getDeclaredMethod("Ha", Object.class).invoke(null, "\\/");
                System.out.println(res);

            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
            System.exit(0);
            //HashMap<String, Integer> encryptedRoutines = getEncryptedRoutines(loaderClasses);
            //HashMap<String, byte[]> moddedClasses = removeEncryptedStrings(obfClasses, loader, encryptedRoutines);

            // Mod Gb.class such that it prints its encryption key
            String name = "obf/Gb.class";
            byte[] GbData = obfClasses.get(name);
            System.out.println(GbData.length);

            ClassNode GbClass = new ClassNode();
            new ClassReader(GbData).accept(GbClass, 0);

            for (MethodNode method : GbClass.methods) {
                //if ((method.name + method.desc).equals("oC" + "(Ljava/lang/String;Z)Ljavax/crypto/Cipher;")) {
                if (method.name.equals("mC")) {
                    //(method.name).equals("mC")
                    System.out.println("Hooked method");
                    ListIterator<AbstractInsnNode> iterator = method.instructions.iterator();
                    /*
                    iterator.add(new InsnNode(Opcodes.ICONST_0));
                    iterator.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V"));
                    */
                    iterator.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;"));
                    iterator.add(new VarInsnNode(Opcodes.ALOAD, 1));
                    //iterator.add(new LdcInsnNode("hello!"));
                    iterator.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V"));
                }
            }

            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            GbClass.accept(writer);
            FileUtils.writeByteArrayToFile(new File("/tmp/patched.class"), writer.toByteArray());
            obfClasses.put(name, writer.toByteArray());
            //repackJar(jar, moddedClasses, "/tmp/new.jar");
            repackJar(jar, obfClasses, "/tmp/new.jar");
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }

        //outputJarEntries(jar);
        System.exit(0);

        JarEntry[] obfClasses = jar.stream().filter(entry -> entry.getName().contains(".class"))
                .toArray(JarEntry[]::new);
        HashMap<String, byte[]> clazzData = new HashMap<>();

        Stream.of(obfClasses).forEach(entry -> {
            try {
                clazzData.put(getClassName(entry.getName()), IOUtils.toByteArray(jar.getInputStream(entry)));
                System.out.println(entry.getName());
            } catch (IOException e) {}
        });

        /*
        removeSyntheticMethodAttributes(clazzData);
        System.exit(0);
        */

        // Need to know var args so we can make a nice wrapper around this
        JarLoader loader = new JarLoader(clazzData);

        /*
        try {
            loader.findClass("obf.Gb");
            byte[] data = loader.loadClassData("obf.Gb");
            // Need to remove synthetic attribute on methods
            FileUtils.writeByteArrayToFile(new File("/tmp/Gb.class"), data);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
        System.exit(0);
        */
        /*
        try {
            Class clazz = loader.findClass("org.tribot.api2007.types.RSCache");
            //Object yJ = clazz.newInstance();
            // Then, we use the reflection api
            Method Ha = clazz.getDeclaredMethod("Ha", Object.class);
            System.out.println(Ha.invoke(null, "asdf"));
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            System.err.println(e.getCause().getMessage());
        }
        System.exit(0);
        */

        //Stream.of(obfClasses).forEach(System.out::println);
        for (String clazzName : clazzData.keySet()) {
            System.out.println(clazzName + ": " + clazzData.get(clazzName).length + " bytes");
        }
        System.out.printf("%d obfuscated classes.\n", obfClasses.length);

        HashMap<String, Integer> encryptedRoutines = new HashMap<>();
        clazzData.keySet().stream()
                .map(clazz -> {
                    ClassReader reader = new ClassReader(clazzData.get(clazz));
                    CustomClassVisitor visitor = new CustomClassVisitor(clazz);
                    reader.accept(visitor, 0);

                    return visitor.encryptionRoutines;
                })
                .flatMap(Collection::stream)
                .forEach(routine -> encryptedRoutines.put(routine, 0));
                //.collect(Collectors.toCollection(LinkedList::new));


        removeEncryptedStrings(clazzData, loader, encryptedRoutines);
        // Unfortunately these do not currently combine.
        System.exit(0);
        //routines.forEach(System.out::println);
        LinkedList<String> strings = clazzData.keySet().stream()
                .flatMap(clazz -> {
                    ClassNode classNode = new ClassNode();
                    new ClassReader(clazzData.get(clazz)).accept(classNode, 0);

                    System.out.println("Scanning methods of " + clazz);
                    return Stream.of(classNode.methods)
                            .flatMap(Collection::stream)
                            //.filter(method -> encryptedRoutines.containsKey(fqcn(clazz, method.name, method.desc)))
                            .map(method -> {
                                /*
                                System.out.printf("[%s] contains call to string encryption routine %s\n", clazz,
                                        fqcn(clazz, method.name, method.desc));
                                */
                                // Iterate over each method's instructions, looking for ldc_w followed by invokestatic
                                LinkedList<String> decryptedStrings = new LinkedList<>();
                                int size = method.instructions.size()-1;
                                for (int i = 0; i < size; i++) {
                                    AbstractInsnNode insn1 = method.instructions.get(i);
                                    AbstractInsnNode insn2 = method.instructions.get(i+1);

                                    if (insn1.getOpcode() == Opcodes.LDC && insn2.getOpcode() == Opcodes.INVOKESTATIC) {
                                        LdcInsnNode string = (LdcInsnNode) insn1;
                                        MethodInsnNode call = (MethodInsnNode) insn2;

                                        if (!encryptedRoutines.containsKey(fqcn(call.owner, call.name, call.desc))) continue;

                                        System.out.printf("[%s] contains call to string encryption routine %s with string %s\n", clazz,
                                                fqcn(call.owner, call.name, call.desc), string.cst);
                                        try {
                                            Class jarClass = loader.findClass((call.owner).replace("/", "."));
                                            //Object yJ = clazz.newInstance();
                                            // Then, we use the reflection api
                                            Method Ha = jarClass.getDeclaredMethod(call.name, Object.class);
                                            String decrypted = (String) Ha.invoke(null, string.cst);
                                            // Simple solution: just add pop instructions.
                                            // Would also be nice to simply log key info to output..
                                            LdcInsnNode decryptedNode = new LdcInsnNode(decrypted);
                                            // Move this elsewhere
                                            method.instructions.insertBefore(decryptedNode, string);
                                            method.instructions.remove(string);
                                            method.instructions.remove(call);
                                            size -= 2;
                                            System.out.println("Decrypted string: " + decrypted);
                                            decryptedStrings.add(decrypted);
                                            //return decrypted;
                                        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                                            System.err.println(e);
                                        }
                                    }
                                }
                                /*
                                ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                                classNode.accept(writer);
                                FileUtils.writeByteArrayToFile(new File(""));
                                */


                                return decryptedStrings;
                            })
                            .flatMap(Collection::stream);
                })
                .collect(Collectors.toCollection(LinkedList::new));

        strings.forEach(System.out::println);

        // Next, find every class that references ANY of these methods
        /*
        clazzData.keySet()
                .forEach(clazz -> {
                    new ClassReader(clazzData.get(clazz)).accept(new EncryptedReferenceVisitor(clazz, encryptedRoutines), 0);
                });

        */
        // Need to find all methods that have the desired signature of
        // static String XX(String input)
        // Input may also be an object, which makes things trickier
    }

    private static HashMap<String, Integer> getEncryptedRoutines(HashMap<String, byte[]> loaderClasses) {
        HashMap<String, Integer> encryptedRoutines = new HashMap<>();
        loaderClasses.keySet().stream()
                .map(clazz -> {
                    ClassReader reader = new ClassReader(loaderClasses.get(clazz));
                    CustomClassVisitor visitor = new CustomClassVisitor(clazz);
                    reader.accept(visitor, 0);

                    return visitor.encryptionRoutines;
                })
                .flatMap(Collection::stream)
                .forEach(routine -> encryptedRoutines.put(routine, 0));

        return encryptedRoutines;
    }

    // Instead of writing, just return the new class mapping?
    private static HashMap<String, byte[]> removeEncryptedStrings(HashMap<String, byte[]> classes, JarLoader loader,
                                               HashMap<String, Integer> encryptedRoutines) {
        HashMap<String, byte[]> modifiedClasses = new HashMap<>();

        int j = 0;
        for (String className : classes.keySet()) {
            System.out.println(className);
            ClassNode classNode = new ClassNode();
            new ClassReader(classes.get(className)).accept(classNode, 0);

            for (MethodNode method : classNode.methods) {
                System.out.println(className + "." + method.name + method.desc);
                int size = method.instructions.size() - 1;
                ListIterator<AbstractInsnNode> iterator = method.instructions.iterator();
                while (iterator.hasNext()) {
                    AbstractInsnNode insn1 = iterator.next();
                    if (!iterator.hasNext()) break;
                    AbstractInsnNode insn2 = iterator.next();

                    if (insn1.getOpcode() == Opcodes.LDC && insn2.getOpcode() == Opcodes.INVOKESTATIC) {
                        LdcInsnNode string = (LdcInsnNode) insn1;
                        MethodInsnNode call = (MethodInsnNode) insn2;

                        if (!encryptedRoutines.containsKey(fqcn(call.owner, call.name, call.desc))) continue;

                        System.out.printf("[%s] contains call to string encryption routine %s with string %s\n", fqcn(className, method.name, method.desc),
                                fqcn(call.owner, call.name, call.desc), string.cst);
                        try {
                            Class jarClass = loader.findClass((call.owner).replace("/", "."));
                            //Object yJ = clazz.newInstance();
                            // Then, we use the reflection api
                            Method Ha = jarClass.getDeclaredMethod(call.name, Object.class);
                            String decrypted = (String) Ha.invoke(null, string.cst);
                            // Simple solution: just add pop instructions.
                            // Would also be nice to simply log key info to output..
                            LdcInsnNode decryptedNode = new LdcInsnNode(decrypted);
                            // Move this elsewhere
                            iterator.previous();
                            iterator.remove();
                            iterator.previous();
                            iterator.remove();
                            iterator.add(decryptedNode);
                            /*
                            method.instructions.insertBefore(decryptedNode, string);
                            method.instructions.remove(string);
                            method.instructions.remove(call);
                            */
                            //size -= 1;
                            System.out.println("Decrypted string: " + decrypted);
                            //decryptedStrings.add(decrypted);
                            //return decrypted;
                        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                            System.err.println("Failed to decrypt string!");
                        }
                    }
                }
            }
            j++;

            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS) {

                // This is broken -- avoid computing stack frames if possible.
                // Otherwise we need to figure out what's wrong
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    try {
                        if (type1 == null) {
                            type1 = "java.lang.Object";
                        }
                        if (type2 == null) {
                            type2 = "java.lang.Object";
                        }

                        type1 = type1.replace("/", ".");
                        type2 = type2.replace("/", ".");

                        // our loader won't find it; do system loader first (if java, for example)?
                        Class clazz1 = loader.findClass(type1);
                        Class clazz2 = loader.findClass(type2);

                        String superName1 = (clazz1.getSuperclass() == null) ? "java.lang.Object" : clazz1.getSuperclass().getName();
                        String superName2 = (clazz2.getSuperclass() == null) ? "java.lang.Object" : clazz2.getSuperclass().getName();

                        // Maybe we should compare the objects directly first?

                        //System.out.println(clazz1.getSuperclass().getName());
                        //System.out.println(clazz2.getSuperclass().getName());

                        /*
                        if (clazz1.getSuperclass() == clazz2.getSuperclass()) {
                            return clazz1.getSuperclass().getName();
                        }
                        */
                        if (superName1.equals(superName2)) {
                            //return clazz1.getSuperclass().getName();
                            return superName1;
                        }

                        //return getCommonSuperClass(clazz1.getSuperclass().getName(), clazz2.getSuperclass().getName());
                        return getCommonSuperClass(superName1, superName2);
                    } catch (ClassNotFoundException e) {
                        System.err.println(e.getMessage());
                        System.err.println("Returning java.lang.Object as common superclass");
                        return "java.lang.Object";
                        //throw new RuntimeException("Failed to find superclass for: " + type1 + "/" + type2);
                    }
                }
            };
            classNode.accept(writer);
            modifiedClasses.put(className, writer.toByteArray());
            //modifiedClasses.put(className.replace(".", "/") + ".class", writer.toByteArray());
            //System.out.println("Modified class: " + className.replace(".", "/") + ".class");
            /*
            try {
                FileUtils.writeByteArrayToFile(new File("/tmp/cleaned/" + className + j + ".class"), writer.toByteArray());
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
            */
        }
        return modifiedClasses;
    }

    // Find all references to an encrypted string method within a class
    static class EncryptedReferenceVisitor extends ClassVisitor {
        private HashMap<String, Integer> routines;
        private String className;

        public EncryptedReferenceVisitor(String className, HashMap<String, Integer> encryptionRoutines) {
            this(Opcodes.ASM8);
            this.routines = encryptionRoutines;
            this.className = className;
        }

        private EncryptedReferenceVisitor(int api) {
            super(api);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);

            return new MethodVisitor(Opcodes.ASM8, methodVisitor) {

                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                    super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                    //System.out.println(fqcn(owner, name, descriptor));

                    if (opcode == Opcodes.INVOKESTATIC && routines.containsKey(fqcn(owner, name, descriptor))) {
                        System.out.printf("[%s] contains call to string encryption routine %s\n", className, fqcn(owner, name, descriptor));
                        // Need to use the tree api from this point on
                        // Read into ClassNode, obtain methods (via filter) and then locate offending instructions.
                        // Once we find the offending instructions, we need to use the class loader to actually load the class,
                        // make a call with the encrypted string, and obtain its decrypted output. Then, we push it onto the
                        // constant pool, and replace with a load instruction.
                    }
                }
            };
        }
    }
    private static String fqcn(String owner, String name, String descriptor) {
        return (owner + "." + name + descriptor).replace("/", ".");
    }

    static class RemoveSyntheticVisitor  extends ClassVisitor {
        public RemoveSyntheticVisitor(ClassVisitor writer) {
            super(Opcodes.ASM8, writer);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            return super.visitMethod(access & (~Opcodes.ACC_SYNTHETIC), name, descriptor, signature, exceptions);
        }
    }

    static class CustomClassVisitor extends ClassVisitor {
        private String className;
        private LinkedList<String> encryptionRoutines;

        public CustomClassVisitor(String className) {
            this(Opcodes.ASM8);
            this.className = className;
            encryptionRoutines = new LinkedList<>();
        }

        private CustomClassVisitor(int api) {
            super(api);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            //System.out.println(name + descriptor);
            if ((access & Opcodes.ACC_STATIC) != 0 && descriptor.equals("(Ljava/lang/Object;)Ljava/lang/String;")) {
                System.out.printf("[%s] string encryption routine found: %s.%s%s\n", className, className, name, descriptor);
                encryptionRoutines.add(fqcn(className, name, descriptor));
            }
            return super.visitMethod(access, name, descriptor, signature, exceptions);
        }
    }

    static class JarLoader extends ClassLoader {
        private HashMap<String, byte[]> classes;
        private HashMap<String, Class> loadedClasses;

        public JarLoader(HashMap<String, byte[]> classes) {
            this.classes = classes;
            loadedClasses = new HashMap<>();
        }

        @Override
        protected Class findClass(String name) throws ClassNotFoundException {
            // Delegate result to parent class loader first
            try {
                //Class clazz = super.findClass(name);
                Class clazz = getParent().loadClass(name);
                if (clazz != null) {
                    return clazz;
                }
            } catch (ClassNotFoundException e) {
            }

            /*
            if (loadedClasses.containsKey(name)) {
                return loadedClasses.get(name);
            }
            */
            // If we couldn't find it anywhere else, must be a local class
            /*
            byte[] classData = loadClassData(name);
            if (classData == null) {
                // Unsure if this is necessary
                classData = classes.get(name);
                Class clazz = defineClass(name, classData, 0, classData.length);
                loadedClasses.put(name, clazz);
                return clazz;
            } else {
                return defineClass(name, classData, 0, classData.length);
            }
            */

            // Make sure we don't try to redefine already loaded classes
            if (loadedClasses.containsKey(name)) {
                return loadedClasses.get(name);
            }

            byte[] classData = loadClassData(name);
            Class clazz = defineClass(name, classData, 0, classData.length);
            loadedClasses.put(name, clazz);

            return clazz;
        }

        private byte[] loadClassData(String name) throws ClassNotFoundException {
            if (classes.containsKey(name)) {
                return classes.get(name);
            }
            throw new ClassNotFoundException("Couldn't load local class: " + name);
            //return null;
        }
    }

    private static void removeSyntheticMethodAttributes(HashMap<String, byte[]> classes) {
        int i = 0;
        // Will I need a classloader for this?
        for (String classname : classes.keySet()) {
            ClassReader reader = new ClassReader(classes.get(classname));
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);

            ClassVisitor visitor = new RemoveSyntheticVisitor(writer);
            reader.accept(visitor, 0);

            try {
                FileUtils.writeByteArrayToFile(new File("/tmp/cleaned/" + classname + i + ".class"), writer.toByteArray());
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
            i += 1;
        }

        /*
        classes.keySet().forEach(classname -> {
            ClassReader reader = new ClassReader(classes.get(classname));
            reader.accept(new RemoveSyntheticVisitor(), 0);
            ClassWriter writer = new ClassWriter(reader, 0);
            try {
                FileUtils.writeByteArrayToFile(new File("/tmp/cleaned/" + classname + i + ".class"), writer.toByteArray());
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
        });
        */
    }
}
