package org.zerock.myapp.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;
import org.zerock.myapp.domain.FileDTO;
import org.zerock.myapp.entity.UpFile;


/**
 * 파일 Repository
 */

@Repository
public interface FileRepository extends JpaRepository<UpFile, Long>, JpaSpecificationExecutor<UpFile> {
	;;
} // end interface
