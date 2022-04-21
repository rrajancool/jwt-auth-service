package murraco.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;


public class BaseResponseDTO {
    @ApiModelProperty(position = 0)
    private Object data;
    @ApiModelProperty(position = 1)
    private String errorMessage;

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
