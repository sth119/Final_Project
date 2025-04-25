package org.zerock.myapp.service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.zerock.myapp.domain.EmployeeDTO;
import org.zerock.myapp.domain.EmployeeHierarchyDTO;
import org.zerock.myapp.domain.FileDTO;
import org.zerock.myapp.entity.Department;
import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.entity.UpFile;
import org.zerock.myapp.persistence.DepartmentRepository;
import org.zerock.myapp.persistence.EmployeeRepository;
import org.zerock.myapp.persistence.FileRepository;

import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor

@Service
public class EmployeeServiceImpl implements EmployeeService {
	@Autowired EmployeeRepository dao;
	@Autowired DepartmentRepository departmentRepository;
	@Autowired BCryptPasswordEncoder bcrypt;
	@Autowired FileServiceImpl fileservice;
	

	@PostConstruct
	void postConstruct() {
		log.debug("EmployeeServiceImpl -- postConstruct() invoked");
		log.debug("dao: {}", dao);
	}// postConstruct

	@Override
	public List<Employee> getAllList() { // 검색 없는 전체 리스트
		log.debug("EmployeeServiceImpl -- getAllList() invoked");

		List<Employee> list = dao.findAll();

		return list;
	} // getAllList

	@Override
	public Page<Employee> getSearchList(EmployeeDTO dto, Pageable paging) {
		log.debug("\t+ EmployeeServiceImpl -- getSearchList(()) invoked", dto);

		Page<Employee> pageList = getSearchListData(dto, paging);

		return pageList;
	} // getSearchList
	
	
	@Override
	public Page<Employee> getSearchListData(EmployeeDTO dto, Pageable paging) {
		log.debug("\t+ EmployeeServiceImpl -- getSearchListData({}) invoked", dto);
		
		if(dto.getSearchWord() != null && dto.getSearchWord().length() == 0) dto.setSearchWord(null);
		if(dto.getSearchText() != null && dto.getSearchText().length() == 0) dto.setSearchText(null);

		if (dto.getSearchText() == null && dto.getDeptId() == null) {
			// 검색 리스트: 활성화상태(true)
			return this.dao.findByEnabled(true, paging);

		} else if (dto.getDeptId() == null && dto.getSearchText() != null) {
			// 리스트: 활성화상태(true) + 이름 or 전화번호
			return switch (dto.getSearchWord()) {
			case "name" -> this.dao.findByEnabledAndNameContaining(true, dto.getSearchText(), paging);
			case "tel" -> this.dao.findByEnabledAndTelContaining(true, dto.getSearchText(), paging);
			default -> throw new IllegalArgumentException("swich_1 - Invalid search word: " + dto.getSearchWord());
			};
		
		} else if(dto.getDeptId() != null && dto.getSearchText() == null) {
			// 리스트: 활성화상태(true) + 부서명
			return this.dao.findByEnabledAndDepartmentId(true, dto.getDeptId(), paging);
		} else if (dto.getDeptId() != null && dto.getSearchText() != null) {
			// 리스트: 활성화상태(true) + 부서명 + 이름 or 전화번호
			return switch (dto.getSearchWord()) {
			case "name" ->
				this.dao.findByEnabledAndDepartmentIdAndNameContaining(true, dto.getDeptId(), dto.getSearchText(), paging);
			case "tel" ->
				this.dao.findByEnabledAndDepartmentIdAndTelContaining(true, dto.getDeptId(), dto.getSearchText(), paging);
			default -> throw new IllegalArgumentException("swich_2 - Invalid search word: " + dto.getSearchWord());
			};
		}

		return null;
	} // getSearchListData

	@Override
	public List<EmployeeHierarchyDTO> findByEnabledAndPositionInOrderByDepartment() {
		Boolean enabled = true;
		Integer[] positions = new Integer[] { 2, 3 }; // 3: 부서장, 2: 팀장
		return dao.findHierarchy(enabled, positions);
	}

	@Override
	public List<Employee> getEmployeesByDepartmentId(Long deptId) {
		return dao.findByEnabledAndDepartment_Id(true, deptId);
	}

// ================= 회원가입 로직 =======================
	@Override
	@Transactional
	public Boolean create(EmployeeDTO dto, MultipartFile file) { // 등록 처리
		log.debug("EmployeeServiceImpl -- create({}) invoked", dto);

		try {
			Department department = this.departmentRepository.findById(dto.getDeptId())
					.orElseThrow(() -> new IllegalArgumentException("유효하지 않은 부서 ID입니다."));

			Employee employee = new Employee();
			String prefix = getRolePrefixFromPosition(dto.getPosition());
			String empno = generateEmpno(prefix, dto.getCrtDate());

			employee.setEmpno(empno); // 사번
			employee.setName(dto.getName()); // 사원 이름 _ front
			employee.setPosition(dto.getPosition()); // 직급 _ front
			employee.setDepartment(department); // 부서 _ front
			employee.setEmail(dto.getEmail()); // 이메일 _ front
			employee.setLoginId(dto.getLoginId()); // 아이디 _ front
			employee.setPassword(dto.getPassword()); // 비밀번호. _ front
			employee.setPassword(bcrypt.encode(employee.getPassword())); // 비밀번호 암호화 저장
			employee.setTel(dto.getTel()); // 전화번호 _ front
			employee.setAddress(dto.getAddress()); // 사원 주소 _ front
			employee.setZipCode(dto.getZipCode()); // 사원 우편번호 _ front
			employee.setEnabled(true); // 0 - 비활성화, 1- 유효

			Employee result = this.dao.save(employee);
			
			if(file != null) this.fileservice.save(file, result);

			return true; // db에 저장.
		} catch (Exception e) {
			throw new IllegalArgumentException("회원가입에 실패했습니다. 다시 시도해 주세요.", e);
		}
	} // 회원가입 로직.

	// ================= 아이디 중복 확인 =======================
	@Override
	public Boolean checkIdDuplicate(String loginId) {
		Boolean isDuplicate = dao.existsByLoginId(loginId);

		return isDuplicate;

	} // 아이디 중복체크 로직

	// ================= 사번 생성 로직2 ( 테스트 중 ) =======================

	// 직급에 따라 알파벳 반환
	@Override
	public String getRolePrefixFromPosition(Integer position) {
		return switch (position) {
		case 1 -> "E"; // 사원
		case 2 -> "E"; // 팀장
		case 3 -> "E"; // 부서장
		case 4 -> "C"; // CEO
		case 5 -> "H"; // 인사관리자
		case 9 -> "A"; // 시스템관리자
		default -> throw new IllegalArgumentException("알 수 없는 직급입니다.");
		};
	}

	@Override
	public String generateEmpno(String rolePrefix, Date date) {
		LocalDate localDate;

		if (date == null) {
			log.warn("generateEmpno: date is null, using current date.");
			localDate = LocalDate.now();
		} else {
			localDate = date.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
		}

		String year = String.valueOf(localDate.getYear()).substring(2);
		String month = String.format("%02d", localDate.getMonthValue());

		String basePrefix = rolePrefix + year + month;

		// 해당 달에 생성된 사번 수 조회 (이건 Repository에 메소드 하나 만들어줘야 함.)
		long count = dao.countByEmpnoStartingWith(basePrefix);

		String seq = String.format("%03d", count + 1);

		return basePrefix + seq;
	} // 사번 생성

	@Override
	public Employee getById(String id) { // 단일 조회
		log.debug("EmployeeServiceImpl -- getById({}) invoked", id);

		// 값이 존재하면 반환하고, 없으면 new Course()와 같은 기본값을 반환합니다.
		Optional<Employee> optional = dao.findById(id);
		if (optional.isPresent()) {
			log.debug("Found: {}", optional.get());
			return optional.get();
		} else {
			log.warn("No employee selected: {}", id);
			return null;
		}
	} // getById

	@Override
	public Boolean update(String empno, EmployeeDTO dto, MultipartFile file) {// 수정 처리
		log.debug("EmployeeServiceImpl -- update({},{},{}) invoked",empno, dto,file);

		try {
			Department department = this.departmentRepository.findById(dto.getDeptId())
					.orElseThrow(() -> new IllegalArgumentException("유효하지 않은 부서 ID입니다."));

			Employee employee = this.dao.findById(dto.getEmpno())
					.orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사원입니다."));

			String newPassword = dto.getPassword();

			employee.setPosition(dto.getPosition()); // 직급 _ front
			employee.setDepartment(department); // 부서 _ front
			employee.setEmail(dto.getEmail()); // 이메일 _ front

			if (newPassword != null && !newPassword.isEmpty()) {
			    employee.setPassword(bcrypt.encode(newPassword));
			} // 비밀번호가 빈값일시 기본 값 유지 & 새로운 값이 있을 시 새로운 값으로 대치 

			employee.setTel(dto.getTel()); // 전화번호 _ front
			employee.setAddress(dto.getAddress()); // 사원 주소 _ front
			employee.setZipCode(dto.getZipCode()); // 사원 우편번호 _ front

			Employee result = this.dao.save(employee);
			
			if(file != null) this.fileservice.save(file, result);
			
			return true; // db에 저장.
		} catch (Exception e) {
			throw new IllegalArgumentException("사원 정보 수정에 실패했습니다. 다시 시도해 주세요.");
		} // try-catch
	} // update

	@Override
	public Boolean deleteById(String id) { // 삭제 처리
		log.debug("EmployeeServiceImpl -- deleteById({}) invoked", id);

		// dao.deleteById(id);
		return true;
	}

}// end class