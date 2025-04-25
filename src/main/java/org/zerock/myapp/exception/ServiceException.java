package org.zerock.myapp.exception;

import java.io.Serial;
import java.io.Serializable;

// Custom User-defined Exception for Services in the Business Layer.
public class ServiceException extends Exception implements Serializable{
	@Serial private static final long serialVersionUID = 1L;
	
	public ServiceException(String message) {
		super(message);
	} // DAOException
	
	public ServiceException(Exception original) {
		super(original);
	} // DAOException
	
	public ServiceException(String message, Exception original) {
		super(message, original);
	} // DAOException

} // end class
