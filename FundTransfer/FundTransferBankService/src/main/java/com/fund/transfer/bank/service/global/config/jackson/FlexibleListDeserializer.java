package com.fund.transfer.bank.service.global.config.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;

import java.io.IOException;
import java.util.List;

public class FlexibleListDeserializer<T> extends JsonDeserializer<List<T>>
        implements ContextualDeserializer {

    private JavaType elementType;

    public FlexibleListDeserializer() {}

    public FlexibleListDeserializer(JavaType elementType) {
        this.elementType = elementType;
    }

    @Override
    public JsonDeserializer<?> createContextual(DeserializationContext ctx, BeanProperty property) {
        // Grabs the generic type T at runtime (e.g. BankAccountModel, UserModel, etc.)
        JavaType wrapperType = property.getType();
        JavaType innerType = wrapperType.containedType(0);
        return new FlexibleListDeserializer<>(innerType);
    }

    @Override
    public List<T> deserialize(JsonParser p, DeserializationContext ctx) throws IOException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonToken token = p.currentToken();

        if (token == JsonToken.START_ARRAY) {
            // already an array → normal deserialization
            JavaType listType = mapper.getTypeFactory()
                    .constructCollectionType(List.class, elementType);
            return mapper.readValue(p, listType);

        } else if (token == JsonToken.START_OBJECT) {
            // single object → wrap in list
            T single = mapper.readValue(p, elementType);
            return List.of(single);

        } else if (token == JsonToken.VALUE_NULL) {
            // null → empty list
            return List.of();
        }

        return List.of();
    }
}