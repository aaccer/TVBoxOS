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

    // public static List<String> splitWords(String text) {
        // List<String> result = new ArrayList<String>();
        // if (text == null || text.trim().isEmpty()) return result;
        // result.add(text);
        // String endFilterRegex = "第[一二三四五六七八九十0-9]+[部季章集话]|(国语|英语|粤语|日语|剪辑|导演剪辑|加长|剧场|配音)版*|\\d+$|(Ⅰ|Ⅱ|Ⅲ|Ⅳ|Ⅴ|Ⅵ|Ⅶ|Ⅷ|Ⅸ|Ⅹ|Ⅺ|Ⅻ)";
        // String filteredText = text.trim().replaceAll(endFilterRegex, " ").trim();
        // if (filteredText.isEmpty()) return result;
        // if (!result.contains(filteredText))result.add(filteredText);
        // Pattern nonWordPattern = Pattern.compile("之|\\W+");
        // String[] rawParts = nonWordPattern.split(filteredText);
        // for (String part : rawParts) {
            // if (part == null  || part.trim().isEmpty()) continue;
            // String finalPart = part.trim().replaceAll(endFilterRegex, "").trim();
            // if (!finalPart.isEmpty() && !result.contains(finalPart)) {
                // result.add(finalPart);
            // }
        // }
        // return result;
    // }
    
    public static List<String> splitWords(String text) {
        List<String> result = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) return result;
    
        String original = text.trim();
        result.add(original);
    
        // ---- 噪声正则 ----
        String noiseRegex ="第?[一二三四五六七八九十百零0-9]+[季部章集话話回期弹彈]"
            + "|(国语|國語|英语|英語|粤语|粵語|日语|日語|韩语|韓語|台语|臺語|闽南语|閩南語|中配|台配|臺配|港配|日配|原声|原聲)(中字|配音|版|无字|無字)*"
            + "|(中字|简中|簡中|繁中|简体|簡體|繁体|繁體|双语|雙語|中文字幕|字幕)"
            + "|(导演剪辑|導演剪輯|剪辑|剪輯|加长|加長|重制|重製|修复|修復|完整|未删减|未刪減)版*"
            + "|(超清|高清|标清|標清|蓝光|藍光|BluRay|WEB-DL|WEBRip|HDRip|HDTV|DVD|REMUX|H265|H264|HEVC|AVC|x264|x265)"
            + "|(4K|8K|1080P|720P|2160P|480P)"
            + "|(TC|TS|CAM|HDTS|HDCAM|DVDSCR|WEB|BDRip|BRRip)"
            + "|(完结|完結|全集|连载|連載|更新至?[一二三四五六七八九十百零0-9]+[集话話期]?)"
            + "|(SP|OVA|OAD|ONA|特别篇|特別篇|特别版|特別版|番外篇?|剧场版?|劇場版?)"
            + "|(?<![A-Za-z])[IVXLCDM]+(?![A-Za-z])"
            + "|[ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩⅪⅫ]"
            + "|[12][0-9]{3}年?"
            + "|^[\\p{IsHan}]{0,3}(动画|動畫|动漫|動漫|电影|電影|电视剧|電視劇|综艺|綜藝|纪录片|紀錄片)"
            + "|[★☆♪♫♥❤✿◆■□▶►※·]"
            + "|\\d+$";

        // ---- 过滤 ----
        String filtered = original.replaceAll(noiseRegex, " ")
                                  .replaceAll("\\s+", " ")
                                  .replaceAll("\\(\\s*\\)|（\\s*）|\\[\\s*\\]|【\\s*】|「\\s*」|『\\s*』|《\\s*》|<\\s*>", "")
                                  .trim();
        if (filtered != null && filtered.length() >= 2 && !result.contains(filtered)) {
            result.add(filtered);
        }

        // ---- 切分（标点） ----       
        Pattern sp1 = Pattern.compile("_|\\W+");    
        // ---- 切分（结构字） ----
        Pattern sp2 = Pattern.compile("[之的与與和在是为為以及或而于於到从從对對向把被让讓使由因]");
    
        for (String part : sp1.split(filtered)) {
            if (part == null) continue;
            String cleaned = part.trim().replaceAll(noiseRegex, "").trim();
            if (cleaned != null && cleaned.length() >= 2 && !result.contains(cleaned)) {
                result.add(cleaned);
            }
            // 结构字切分
            if (!cleaned.isEmpty()) {
                for (String sub : sp2.split(cleaned)) {
                    String subCleaned = sub.trim().replaceAll(noiseRegex, "").trim();
                    if (subCleaned != null && subCleaned.length() >= 2 && !result.contains(subCleaned)) {
                        result.add(subCleaned);
                    }
                }
            }
        }
        return result;
    }
    
    
}
