package com.yolt.secretspipeline.secrets;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class Environment implements Comparable<Environment> {

    @NonNull
    String name;
    @NonNull
    Environments.Namespace namespace;
    @NonNull
    String cluster;
    boolean prd;

    public String getPath() {
        return (prd ? "prd/" : "dta/") + name + "/" + cluster + "/" + namespace;
    }

    @Override
    public int compareTo(Environment o) {
        return getPath().compareTo(o.getPath());
    }
}
