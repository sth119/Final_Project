package org.zerock.myapp.exception;

import java.io.Serial;
import java.io.Serializable;

// Custom User-defined Exception for DAOs in the Persistence Layer.
public class DAOException extends Exception implements Serializable{
	@Serial private static final long serialVersionUID = 1L;
	
	public DAOException(String message) {
		super(message);
	} // DAOException
	
	public DAOException(Exception original) {
		super(original);
	} // DAOException
	
	public DAOException(String message, Exception original) {
		super(message, original);
	} // DAOException

} // end class
