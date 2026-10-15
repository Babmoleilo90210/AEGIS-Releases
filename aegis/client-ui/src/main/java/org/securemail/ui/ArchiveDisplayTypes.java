package org.securemail.ui;

/** Presentation labels only. Archive and filter identifiers remain unchanged on disk. */
final class ArchiveDisplayTypes {
    private ArchiveDisplayTypes() { }
    static String label(String id) {
        return switch (id == null ? "" : id) {
            case "letter" -> "Письмо";
            case "text" -> "Текст";
            case "image" -> "Изображение";
            case "pdf" -> "PDF-документ";
            case "file" -> "Файл";
            case "folder" -> "Папка";
            case "", "Все типы" -> "Все типы";
            default -> "Файл";
        };
    }
}
