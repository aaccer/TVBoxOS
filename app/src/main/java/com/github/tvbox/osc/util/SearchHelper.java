package com.github.tvbox.osc.util;

import com.github.tvbox.osc.api.ApiConfig;
import com.github.tvbox.osc.bean.SourceBean;
import com.github.tvbox.osc.ui.activity.SearchActivity;
import com.orhanobut.hawk.Hawk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

public class SearchHelper {

    public static HashMap<String, String> getSourcesForSearch() {
        HashMap<String, String> mCheckSources;
        try {
            String api = Hawk.get(HawkConfig.API_URL, "");
            if(api.isEmpty())return null;
            HashMap<String, HashMap<String, String>> mCheckSourcesForApi = Hawk.get(HawkConfig.SOURCES_FOR_SEARCH, new HashMap<>());
            mCheckSources = mCheckSourcesForApi.get(api);
        } catch (Exception e) {
            return null;
        }
        if (mCheckSources == null || mCheckSources.isEmpty()) mCheckSources = getSources();
        return mCheckSources;
    }

    public static void putCheckedSources(HashMap<String, String> mCheckSources,boolean isAll) {
        String api = Hawk.get(HawkConfig.API_URL, "");
        if (api.isEmpty()) {
            return;
        }
        HashMap<String, HashMap<String, String>> mCheckSourcesForApi = Hawk.get(HawkConfig.SOURCES_FOR_SEARCH,null);

        if(isAll){
            if (mCheckSourcesForApi == null) return;
            if (mCheckSourcesForApi.containsKey(api)) mCheckSourcesForApi.remove(api);
        }else {
            if (mCheckSourcesForApi == null) mCheckSourcesForApi = new HashMap<>();
            mCheckSourcesForApi.put(api, mCheckSources);
        }
        SearchActivity.setCheckedSourcesForSearch(mCheckSources);
        Hawk.put(HawkConfig.SOURCES_FOR_SEARCH, mCheckSourcesForApi);
    }

    public static HashMap<String, String> getSources(){
        HashMap<String, String> mCheckSources = new HashMap<>();
        for (SourceBean bean : ApiConfig.get().getSourceBeanList()) {
            if (!bean.isSearchable()) {
                continue;
            }
            mCheckSources.put(bean.getKey(), "1");
        }
        return mCheckSources;
    }

    // public static List<String> splitWords(String text) {
        // List<String> result = new ArrayList<>();
        // result.add(text);
        // String[] parts = text.split("\\W+");
        // if (parts.length > 1) {
            // result.addAll(Arrays.asList(parts));
        // }
        // return result;
    // }

    public static List<String> splitWords(String text) {
        List<String> result = new ArrayList<String>();
        if (text == null || text.trim().isEmpty()) return result;
        result.add(text);
        String endFilterRegex = "第[一二三四五六七八九十0-9]+[部季章集话]|(国语|英语|粤语|日语|剪辑|导演剪辑|加长|剧场|配音)版*|\\d+$|(Ⅰ|Ⅱ|Ⅲ|Ⅳ|Ⅴ|Ⅵ|Ⅶ|Ⅷ|Ⅸ|Ⅹ|Ⅺ|Ⅻ)";
        String filteredText = text.trim().replaceAll(endFilterRegex, " ").trim();
        if (filteredText.isEmpty()) return result;
        if (!result.contains(filteredText))result.add(filteredText);
        Pattern nonWordPattern = Pattern.compile("之|\\W+");
        String[] rawParts = nonWordPattern.split(filteredText);
        for (String part : rawParts) {
            if (part == null  || part.trim().isEmpty()) continue;
            String finalPart = part.trim().replaceAll(endFilterRegex, "").trim();
            if (!finalPart.isEmpty() && !result.contains(finalPart)) {
                result.add(finalPart);
            }
        }
        return result;
    }
}
