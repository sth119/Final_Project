package org.zerock.myapp.service;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;
import org.zerock.myapp.entity.Employee;

public interface FileService {
	
	public Boolean save(MultipartFile file, Employee employee);
	Resource getFile(String fileName);
	
}//end interface