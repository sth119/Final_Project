package org.zerock.myapp.util;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@NoArgsConstructor

//autoApply가 true로 설정되면, 해당 컨버터는 모든 Boolean 필드에 자동으로 적용됩니다.
@Converter(autoApply = true)
public class BooleanToIntegerConverter implements AttributeConverter<Boolean, Integer> {
	
	
	@Override
	public Integer convertToDatabaseColumn(Boolean attr) {
//		log.debug("convertToDatabaseColumn({}) invoked.", attr);
		return (attr != null && attr) ? 1 : 0;	// true -> 1, false -> 0
	}

	@Override
	public Boolean convertToEntityAttribute(Integer col) {
//		log.debug("convertToEntityAttribute({}) invoked.", col);
		return (col != null && col == 1);	// 1 -> true, 0 -> false
	}

}//end class
