package com.yolt.secretspipeline.command.io;

import com.yolt.secretspipeline.secrets.Base64String;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class FileContents {

    private final String path;
    private final Base64String contents;
}
