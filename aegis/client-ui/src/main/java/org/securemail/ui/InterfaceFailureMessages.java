package org.securemail.ui;

import java.io.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;

/** User text is explicit and bounded; diagnostics retain types, never raw paths or parser input. */
final class InterfaceFailureMessages {
    private InterfaceFailureMessages() {}
    private static final Set<String> APPEARANCE=Set.of(
        "Недостаточный контраст текста (нужно 4,5:1)","Недостаточный контраст подписей (нужно 3:1)",
        "Недопустимое имя шрифта","Слишком узкая область просмотра","Недопустимое изображение",
        "Выберите фоновое изображение","Проверьте расписание","Цвет должен иметь формат #RRGGBB",
        "Недопустимое название","Значение вне допустимого диапазона","Некорректный порядок элементов",
        "Неизвестная тема","Название уже существует или достигнут лимит тем","Встроенные темы неизменяемы",
        "Название уже существует","Достигнут лимит макетов","Выберите сохранённый макет",
        "Фоновое изображение недоступно","Выберите тему","Фон выберите локально после импорта",
        "Тема недоступна","Фон слишком близок к цвету текста","Достигнут лимит настроек оформления",
        "Выберите обычный JPG, PNG или WebP","Изображение превышает допустимый размер",
        "Поддерживаются JPG, PNG и WebP","Слишком большое разрешение изображения",
        "Не удалось безопасно декодировать изображение","Не удалось подготовить фон","Повреждённое изображение");
    private static final Set<String> ARCHIVE=Set.of(
        "Архив уже открыт","Архив уже существует","Для нового архива выберите пустую папку",
        "Контейнер архива не найден","Нет локальной отметки целостности. Откройте как перенесённый архив после проверки.",
        "Повреждена отметка целостности","Обнаружен откат или подмена архива. Восстановление выполняйте над копией.",
        "Достигнут лимит метаданных","Неподдерживаемая схема архива","Повреждены настройки архива",
        "Повреждён каталог архива","Повтор объекта архива","Архив достиг лимита размера",
        "Некорректный лимит или таймер","Объект недоступен","Достигнут лимит объектов архива",
        "Папки: не более 12 уровней, без циклов","Папка недоступна","Окончательно удалять можно только из корзины",
        "Выберите обычный файл","Файл: не более 1 ГБ","Недостаточно места в лимите архива",
        "Файл архива повреждён","Для этого файла используйте экспорт","Нарушена целостность файла",
        "Выберите файл вне корзины","Выберите новое имя вне контейнера","Размер файла изменился",
        "Файл обрезан","Архив заблокирован","Некорректный идентификатор","Расписание: не более 7 дней",
        "Папка копий должна быть вне архива","Выберите другой архив","Повреждена структура папок",
        "Повреждён источник объединения","Выберите новое имя для диагностической копии",
        "Копия должна быть вне оригинала","Неожиданная структура контейнера","Неожиданный файл в контейнере",
        "Поисковый индекс повреждён. Перестройте его; файлы сохраняются.","Операция отменена");
    static String appearance(Exception error){
        String text=error.getMessage();
        if(APPEARANCE.contains(Objects.requireNonNullElse(text,"")))return text;
        if(error instanceof AccessDeniedException)return "Нет доступа к файлу оформления. Проверьте права выбранной папки.";
        if(error instanceof NoSuchFileException||error instanceof FileNotFoundException)return "Файл оформления не найден. Выберите доступный файл.";
        if(error instanceof java.time.DateTimeException)return "Проверьте время переключения темы: нужен формат ЧЧ:ММ.";
        return "Не удалось изменить оформление. Проверьте выбранный файл и значения.";
    }
    static String archive(Exception error){
        if(error instanceof GeneralSecurityException)return "Неверный пароль, ключ восстановления или повреждён архив";
        String text=error.getMessage();
        if(ARCHIVE.contains(Objects.requireNonNullElse(text,"")))return text;
        if(Set.of("Symlink в архиве запрещён","Symlink в пути архива запрещён","Symlink в контейнере").contains(Objects.requireNonNullElse(text,"")))return "Символические ссылки в архиве и пути к нему запрещены. Выберите обычную папку.";
        if("Anchor нельзя хранить внутри контейнера".equals(text))return "Локальную отметку целостности нужно хранить вне контейнера архива.";
        if(error instanceof AccessDeniedException)return "Нет доступа к файлу архива. Проверьте права выбранной папки.";
        if(error instanceof NoSuchFileException||error instanceof FileNotFoundException)return "Файл или папка архива не найдены. Проверьте выбранное расположение.";
        if(error instanceof FileAlreadyExistsException)return "Файл уже существует. Выберите новое имя.";
        if(error instanceof InterruptedIOException)return "Операция архива отменена.";
        return "Не удалось выполнить операцию архива. Проверьте файл, папку и доступное место.";
    }
    static List<String> diagnostic(Throwable error){
        List<String> types=new ArrayList<>();Set<Throwable> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        for(Throwable cause=error;cause!=null&&types.size()<4&&seen.add(cause);cause=cause.getCause())types.add(cause.getClass().getName());
        return List.copyOf(types);
    }
}
