package com.yolt.secretspipeline.command;

import lombok.Value;

@Value
public class Options {

    boolean dryRun;
    boolean usePRDVault;
    String originalMR;

}
