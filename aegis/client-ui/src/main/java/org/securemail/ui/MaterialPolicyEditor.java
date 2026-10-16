package org.securemail.ui;
import com.google.gson.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import static org.securemail.ui.CommunityUi.*;
/** Organization scope is the default. Geography never changes the access policy. */
final class MaterialPolicyEditor {
 private final ComboBox<String> audience=new ComboBox<>();private final String organization;
 private final TextField level=field("Минимальный уровень"),permissions=field("Дополнительные полномочия"),organizations=field("Разрешённые организации"),users=field("Разрешённые пользователи");private final CheckBox offline=new CheckBox("Разрешить защищённый офлайн-кэш");
 MaterialPolicyEditor(JsonObject material){this(material,material==null?"":str(material,"organization"));}
 MaterialPolicyEditor(JsonObject material,String organization){this.organization=organization;audience.getItems().setAll("В пределах организации; без организации — всем пользователям","Всем пользователям с необходимыми правами");audience.getSelectionModel().selectFirst();audience.setMinWidth(0);audience.setMaxWidth(Double.MAX_VALUE);level.setText("0");if(material!=null&&material.has("policy")&&material.get("policy").isJsonObject()){JsonObject policy=material.getAsJsonObject("policy");if(str(policy,"scope").equals("GLOBAL"))audience.getSelectionModel().select(1);level.setText(Long.toString(number(policy,"minimumLevel")));permissions.setText(RoleBuilder.join(array(policy,"permissions")));organizations.setText(RoleBuilder.join(array(policy,"organizations")));users.setText(RoleBuilder.join(array(policy,"users")));offline.setSelected(str(policy,"offlineAllowed").equals("true"));}}
 Node node(){return fold("Видимость и доступ",card(audience,level,permissions,organizations,users,offline,label("Списки пользователей и организаций дополнительно ограничивают доступ. Публикация в городской ленте не отменяет ограничения.")));}
 JsonObject value(){return value(organization);}
 JsonObject value(String currentOrganization){int minimum;try{minimum=Integer.parseInt(level.getText());}catch(Exception invalid){minimum=-1;}String scope=audience.getSelectionModel().getSelectedIndex()==1||currentOrganization==null||currentOrganization.isBlank()?"GLOBAL":"ORG:"+currentOrganization.trim();return obj("scope",scope,"minimumLevel",minimum,"permissions",strings(permissions.getText()),"organizations",strings(organizations.getText()),"users",strings(users.getText()),"offlineAllowed",offline.isSelected());}
}
