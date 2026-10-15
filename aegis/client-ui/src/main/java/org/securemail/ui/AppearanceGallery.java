package org.securemail.ui;

import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.canvas.Canvas;
import javafx.scene.control.Button;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.TilePane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.SVGPath;
import org.securemail.client.appearance.Appearance;
import org.securemail.client.appearance.AppearanceStore;

/** Preset cards use layout panes throughout; favorites never cover the preview or name. */
final class AppearanceGallery extends TilePane {
    private final AppearanceStore store;
    private final Consumer<Appearance.Theme> choose;
    private final Consumer<Exception> failure;

    AppearanceGallery(AppearanceStore store, Consumer<Appearance.Theme> choose,
                      Consumer<Exception> failure) {
        super(10, 10);
        this.store = store;
        this.choose = choose;
        this.failure = failure;
        setId("appearance-gallery");
        setMinWidth(0);
        setPrefTileWidth(230);
        setPrefColumns(3);
        setTileAlignment(Pos.TOP_LEFT);
    }

    void refresh(String query, String category, boolean favoritesOnly) {
        getChildren().clear();
        String term = query == null ? "" : query.strip().toLowerCase(Locale.ROOT);
        for (Appearance.Theme theme : store.themes().values()) {
            if (!theme.name().toLowerCase(Locale.ROOT).contains(term)
                    || category != null && !category.equals("Все") && !theme.category().toString().equals(category)
                    || favoritesOnly && !store.favorites().contains(theme.id())) continue;
            Button select = new Button(theme.name(), preview(theme));
            select.setId("preset-" + theme.id());
            select.getStyleClass().addAll("preset-preview", "wrapped-action");
            select.setContentDisplay(ContentDisplay.TOP);
            select.setWrapText(true);
            select.setMinWidth(0);
            select.setMaxWidth(Double.MAX_VALUE);
            select.setAccessibleText("Предпросмотр " + theme.name());
            select.setOnAction(event -> choose.accept(theme));

            boolean favorite = store.favorites().contains(theme.id());
            Button pin = new Button();
            pin.setId("preset-favorite-" + theme.id());
            pin.setGraphic(star(favorite));
            pin.setTooltip(new Tooltip(favorite ? "Убрать из избранного" : "В избранное"));
            pin.setAccessibleText((favorite ? "Убрать из избранного: " : "В избранное: ") + theme.name());
            pin.setMinWidth(36);
            pin.setPrefWidth(36);
            pin.setMaxWidth(36);
            pin.setOnAction(event -> {
                try {
                    store.favorite(theme.id(), !store.favorites().contains(theme.id()));
                    refresh(query, category, favoritesOnly);
                } catch (Exception invalid) { failure.accept(invalid); }
            });
            Label type = new Label(theme.category().toString());
            type.setWrapText(true);
            type.setMinWidth(0);
            type.getStyleClass().add("muted");
            HBox.setHgrow(type, Priority.ALWAYS);
            type.setMaxWidth(Double.MAX_VALUE);
            HBox metadata = new HBox(8, type, pin);
            metadata.setAlignment(Pos.CENTER_LEFT);
            VBox card = new VBox(8, select, metadata);
            card.setId("preset-card-" + theme.id());
            card.getStyleClass().add("preset-tile");
            card.setStyle("-fx-padding: 8;");
            card.setMinWidth(0);
            card.setPrefWidth(230);
            card.setMaxWidth(230);
            getChildren().add(card);
        }
    }

    static SVGPath star(boolean selected) {
        SVGPath shape = new SVGPath();
        shape.setContent("M9 1.2 11.3 6 16.6 6.7 12.8 10.4 13.7 15.7 9 13.2 4.3 15.7 5.2 10.4 1.4 6.7 6.7 6 Z");
        shape.setStyle("-fx-stroke: -aegis-accent; -fx-stroke-width: 1.5; -fx-fill: "
                + (selected ? "-aegis-accent" : "transparent") + ";");
        return shape;
    }

    private static Canvas preview(Appearance.Theme theme) {
        Canvas canvas = new Canvas(160, 74);
        canvas.setAccessibleText("Миниатюра " + theme.name());
        var g = canvas.getGraphicsContext2D();
        var p = theme.palette();
        double radius = Math.min(12, theme.radius());
        g.setFill(Color.web(p.background()));
        g.fillRoundRect(0, 0, 160, 74, radius, radius);
        g.setFill(Color.web(p.panel()));
        g.fillRoundRect(5, 5, 28, 64, radius, radius);
        g.setFill(Color.web(p.accent()));
        g.fillOval(13, 12, 12, 12);
        g.setFill(Color.web(p.muted()));
        for (int y : List.of(33, 43, 53)) g.fillRoundRect(11, y, 16, 3, 2, 2);
        for (int i = 0; i < 3; i++) {
            int y = 7 + i * 21;
            g.setFill(Color.web(i == 0 ? p.incoming() : i == 1 ? p.outgoing() : p.control()));
            g.fillRoundRect(39, y, 115, 17, radius, radius);
            g.setFill(Color.web(p.text()));
            g.fillRoundRect(45, y + 5, i == 1 ? 74 : 55, 3, 2, 2);
            g.setFill(Color.web(p.muted()));
            g.fillRoundRect(45, y + 11, i == 2 ? 46 : 88, 2, 2, 2);
        }
        return canvas;
    }
}
