package com.github.tvbox.osc.util.thunder;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.text.TextUtils;
import android.util.Log;

import com.xunlei.downloadlib.XLDownloadManager;
import com.xunlei.downloadlib.XLTaskHelper;
import com.xunlei.downloadlib.android.XLUtil;
import com.xunlei.downloadlib.parameter.TorrentFileInfo;
import com.xunlei.downloadlib.parameter.TorrentInfo;
import com.xunlei.downloadlib.parameter.XLTaskInfo;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Thunder {

    private static String cacheRoot = "";
    private static String localPath = "";
    private static String name = "";
    private static String task_url = "";
    private static long currentTask = 0L;
    private static ArrayList<TorrentFileInfo> torrentFileInfoArrayList = null;
    private static ExecutorService threadPool = null;


    private static void init(Context context) {
        // fake deviceId and Mac
        SharedPreferences sharedPreferences = context.getSharedPreferences("rand_thunder_id", Context.MODE_PRIVATE);
        String imei = sharedPreferences.getString("imei", null);
        String mac = sharedPreferences.getString("mac", null);
        if (imei == null) {
            imei = randomImei();
            sharedPreferences.edit().putString("imei", imei).commit();
        }
        if (mac == null) {
            mac = randomMac();
            sharedPreferences.edit().putString("mac", mac).commit();
        }

        XLUtil.mIMEI = imei;
        XLUtil.isGetIMEI = true;
        XLUtil.mMAC = mac;
        XLUtil.isGetMAC = true;
        String cd3 = "cee25055f125a2fde0";
        String base64Decode = "axzNjAwMQ^^yb==0^852^083dbcff^";
        String substring = base64Decode.substring(1);
        String substring2 = cd3.substring(0, cd3.length() - 1);
        String cd = substring + substring2;
        XLTaskHelper.init(context, cd, "21.01.07.800002");
        cacheRoot = context.getCacheDir().getAbsolutePath() + File.separator + "thunder";
    }

    public static void stop(Boolean bool) {
        if (currentTask > 0) {
            XLTaskHelper.instance().stopTask(currentTask);
            currentTask = 0L;
        }
        if(bool){
            torrentFileInfoArrayList = null;
            // del cache file
            File cache = new File(task_url.isEmpty()?cacheRoot:localPath);
            recursiveDelete(cache);
            if (!cache.exists())
                cache.mkdirs();
            if (threadPool != null) {
                try {
                    threadPool.shutdownNow();
                    threadPool = null;
                } catch (Throwable th) {

                }
            }
        }
    }

    public interface ThunderCallback {

        void status(int code, String info);

        void list(String playList);

        void play(String url);
    }

    public static void parse(Context context, List<String> urlList, ThunderCallback callback) {
        init(context);
        stop(true);
        threadPool = Executors.newSingleThreadExecutor();
        ArrayList<String> playList = new ArrayList<>();
        torrentFileInfoArrayList=new ArrayList<>();
        threadPool.execute(new Runnable() {
            @Override
            public void run() {
                for (String url : urlList) {
                    if (isMagnet(url) || isThunder(url) || isTorrent(url)) {
                        String link = isThunder(url) ? XLDownloadManager.getInstance().parserThunderUrl(url) : url;
                        Uri p = Uri.parse(link);
                        if (p == null) {
                            continue;
                        }
                        String fileName = XLTaskHelper.instance().getFileName(link);
                        File cache = new File(cacheRoot + File.separator + fileName);
                        try {
                            currentTask = isMagnet(url) ?
                                    XLTaskHelper.instance().addMagentTask(url, cacheRoot, fileName) :
                                    XLTaskHelper.instance().addThunderTask(url, cacheRoot, fileName);
                        } catch (Exception exception) {
                            exception.printStackTrace();
                            currentTask = 0;
                        }
                        if (currentTask <= 0) {
                            continue;
                        }
                        int count = 20;
                        Boolean conti=true;
                        while (conti) {
                            count--;
                            if (count <= 0) {
                                conti=false;
                            }
                            XLTaskInfo taskInfo = XLTaskHelper.instance().getTaskInfo(currentTask);
                            switch (taskInfo.mTaskStatus) {
                                case 2: {
                                    try {
                                        TorrentInfo torrentInfo = XLTaskHelper.instance().getTorrentInfo(cache.getAbsolutePath());
                                        if (torrentInfo == null || TextUtils.isEmpty(torrentInfo.mInfoHash)) {
                                        } else {
                                            TorrentFileInfo[] mSubFileInfo = torrentInfo.mSubFileInfo;
                                            if (mSubFileInfo != null && mSubFileInfo.length >= 0) {

                                                for (TorrentFileInfo sub : mSubFileInfo) {
                                                    if (isMedia(sub.mFileName)) {
                                                        sub.torrentPath = cache.getAbsolutePath();
                                                        playList.add(sub.mFileName + "$tvbox-torrent:" + torrentFileInfoArrayList.size());
                                                        torrentFileInfoArrayList.add(sub);
                                                    }
                                                }
                                                conti=false;
                                            }
                                        }
                                    } catch (Throwable throwable) {
                                        throwable.printStackTrace();
                                    }
                                }
                                default: {
                                }
                            }
                            try {
                                Thread.sleep(100);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
                if (playList.size() > 0) {
                    callback.list(TextUtils.join("#", playList));
                } else {
                    callback.status(-1, "文件列表为空!");
                }
            }});



//        if(isEd2k(url) || isFtp(url)){
//            task_url= url;
//            System.out.println("startTask:");
//            threadPool.execute(new Runnable() {
//                @Override
//                public void run() {
//                        System.out.println("task_url: "+task_url);
//                        if(TextUtils.isEmpty(task_url) || currentTask != 0L){
//                            return;
//                        }
//                        if(isNetworkDownloadTask(task_url)){
//                            name = XLTaskHelper.instance().getFileName(task_url);
//                            localPath = (new File(cacheRoot+File.separator+"temp",getFileNameWithoutExt(name)))+"/";
//                            currentTask = XLTaskHelper.instance().addThunderTask(task_url, localPath, null);
//                            callback.list(name+"$"+task_url);
//                            System.out.println("init name:"+name);
//                        } else {
//                            currentTask = 0L;
//                        }
//                        System.out.println("name: "+name);
//                        Log.d("TAG", "startTask(" +task_url + "), taskId = " + currentTask);
//                }
//            });
//        }
    }


    public static boolean play(String url, ThunderCallback callback) {
        if (url.startsWith("tvbox-torrent:")) {
            int idx = Integer.parseInt(url.substring(14));
            TorrentFileInfo info = torrentFileInfoArrayList.get(idx);
            if (currentTask > 0) {
                XLTaskHelper.instance().stopTask(currentTask);
                currentTask = 0L;
            }
            threadPool.execute(new Runnable() {
                @Override
                public void run() {
                    String torrentName = new File(info.torrentPath).getName();
                    String cache = cacheRoot + File.separator + torrentName.substring(0, torrentName.lastIndexOf("."));
                    currentTask = XLTaskHelper.instance().addTorrentTask(info.torrentPath, cache, info.mFileIndex);
                    if (currentTask < 0)
                        callback.status(-1, "下载出错");
                    int count = 30;
                    while (true) {
                        count--;
                        if (count <= 0) {
                            callback.status(-1, "解析下载超时");
                            break;
                        }
                        XLTaskInfo taskInfo = XLTaskHelper.instance().getBtSubTaskInfo(currentTask, info.mFileIndex).mTaskInfo;
                        switch (taskInfo.mTaskStatus) {
                            case 3: {
                                callback.status(-1, errorInfo(taskInfo.mErrorCode));
                                return;
                            }
                            case 1:
                            case 4: // 下载中
                            case 2: { // 下载完成
                                String pUrl = XLTaskHelper.instance().getLoclUrl(cache + File.separator + info.mFileName);
                                callback.play(pUrl);
                                return;
                            }
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            });
            return true;
        }
        if (isEd2k(url) || isFtp(url)) {
            threadPool.execute(new Runnable() {
                @Override
                public void run() {

                    int count = 20;
                    while (true) {
                        count--;
                        if (count <= 0) {
                            callback.status(-1, "解析下载超时");
                            break;
                        }
                        String playUrl=getPlayUrl();
                        if(!playUrl.isEmpty()){
                            callback.play(playUrl);
                            return;
                        }
//                        XLTaskInfo taskInfo = getTaskInfo();
//                        switch (taskInfo.mTaskStatus) {
//                            case 3: {
//                                callback.status(-1, errorInfo(taskInfo.mErrorCode));
//                                return;
//                            }
//                            case 1:{
//                                if(taskInfo.mDownloadSize>0){
//                                    String playUrl=getPlayUrl();
//                                    callback.play(playUrl);
//                                    return;
//                                }
//                            }
//                            case 4: // 下载中
//                            case 2: { // 下载完成
//                                String playUrl=getPlayUrl();
//                                callback.play(playUrl);
//                                return;
//                            }
//                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            });
            return true;
        }
        return false;
    }

    private static String errorInfo(int code) {
        switch (code) {
            case 9125:
                return "文件名太长";
            case 111120:
                return "文件路径太长";
            case 111142:
                return "文件太小";
            case 111085:
                return "磁盘空间不足";
            case 111171:
                return "拒绝的网络连接";
            case 9301:
                return "缓冲区不足";
            case 114001:
            case 114004:
            case 114005:
            case 114006:
            case 114007:
            case 114011:
            case 9304:
            case 111154:
                return "版权限制：无权下载";
            case 114101:
                return "无效链接";
            default:
                return "ErrorCode=" + code;
        }
    }


    public static boolean isSupportUrl(String url) {
//        return isMagnet(url) || isThunder(url) || isEd2k(url) || isFtp(url);
        return isMagnet(url) || isThunder(url) || isTorrent(url);
    }

    private static boolean isMagnet(String url) {
        return url.toLowerCase().startsWith("magnet:");
    }

    private static boolean isThunder(String url) {
        return url.toLowerCase().startsWith("thunder");
    }

    private static boolean isTorrent(String url) {
        return url.toLowerCase().split(";")[0].endsWith(".torrent");
    }

    private static boolean isEd2k(String url) {
        return url.toLowerCase().startsWith("ed2k:");
    }

    public static boolean isFtp(String url) {
        return url.toLowerCase().startsWith("ftp://");
    }

    static void recursiveDelete(File file) {
        if (!file.exists())
            return;
        if (file.isDirectory()) {
            for (File f : file.listFiles()) {
                recursiveDelete(f);
            }
        }
        file.delete();
    }

    static ArrayList<String> formats = new ArrayList<>();

    static boolean isMedia(String name) {
        if (formats.size() == 0) {
            formats.add(".rmvb");
            formats.add(".avi");
            formats.add(".mkv");
            formats.add(".flv");
            formats.add(".mp4");
            formats.add(".rm");
            formats.add(".vob");
            formats.add(".wmv");
            formats.add(".mov");
            formats.add(".3gp");
            formats.add(".asf");
            formats.add("mpg");
            formats.add("mpeg");
            formats.add("mpe");
        }
        for (String f : formats) {
            if (name.toLowerCase().endsWith(f))
                return true;

        }
        return false;
    }

    static String randomImei() {
        return randomString("0123456", 15);
    }

    static String randomMac() {
        return randomString("ABCDEF0123456", 12).toUpperCase();
    }

    static String randomString(String base, int length) {
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }


    public static boolean isNetworkDownloadTask(String url){
        if(TextUtils.isEmpty(url)) return false;
        if(isFtp(url) || isEd2k(url)){
            return true;
        }else{
            return false;
        }
    }

    public static void startTask(Context context, String url, ThunderCallback callback){
        init(context);
        stop(true);
        task_url= url;
        System.out.println("checkThunder: "+task_url);
        System.out.println("startTask:");
        threadPool = Executors.newSingleThreadExecutor();
        threadPool.execute(new Runnable() {
            @Override
            public void run() {
                if (isEd2k(task_url) || isFtp(task_url)) {
                    System.out.println("task_url: "+task_url);
                    if(TextUtils.isEmpty(task_url) || currentTask != 0L){
                        return;
                    }
                    if(isNetworkDownloadTask(task_url)){
                        name = XLTaskHelper.instance().getFileName(task_url);
                        localPath = (new File(cacheRoot+File.separator+"temp",getFileNameWithoutExt(name)))+"/";
                        currentTask = XLTaskHelper.instance().addThunderTask(task_url, localPath, null);
                        callback.list(name+"$"+task_url);
                        System.out.println("init name:"+name);
                    } else {
                        currentTask = 0L;
                    }
                    System.out.println("name: "+name);
                    Log.d("TAG", "startTask(" +task_url + "), taskId = " + currentTask);
                }
            }
        });
    }

    public static void stopTask(){
        if(currentTask != 0L){
            XLTaskHelper.instance().deleteTask(currentTask, task_url.isEmpty()?cacheRoot:localPath);
            currentTask = 0L;
        }
    }
    public static XLTaskInfo getTaskInfo(){
        return XLTaskHelper.instance().getTaskInfo(currentTask);
    }

    public static String getPlayUrl(){
            if(currentTask != 0L){
                if(isNetworkDownloadTask(task_url)){
                    return XLTaskHelper.instance().getLoclUrl(localPath + name);
                }
        }
        return null;
    }

    public static String getFileNameWithoutExt(String filePath){
        if(TextUtils.isEmpty(filePath)) return "";
        String fileName = filePath;
        int p = fileName.lastIndexOf(File.separatorChar);
        if(p != -1){
            fileName = fileName.substring(p + 1);
        }
        p = fileName.indexOf('.');
        if(p != -1){
            fileName = fileName.substring(0, p);
        }
        return fileName;
    }

}
