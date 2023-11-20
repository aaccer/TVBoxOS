package xyz.doikki.videoplayer.exo;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.net.TrafficStats;
import android.view.Surface;
import android.view.SurfaceHolder;

import androidx.annotation.NonNull;

import com.github.tvbox.osc.base.App;
import com.github.tvbox.osc.util.HawkConfig;
import com.github.tvbox.osc.util.LOG;
import com.google.android.exoplayer2.DefaultLoadControl;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.ExoPlayer;
import com.google.android.exoplayer2.LoadControl;
import com.google.android.exoplayer2.PlaybackException;
import com.google.android.exoplayer2.PlaybackParameters;
import com.google.android.exoplayer2.Player;

import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.trackselection.TrackSelectionArray;

import com.google.android.exoplayer2.video.VideoSize;
import com.orhanobut.hawk.Hawk;

import java.util.Map;

import xyz.doikki.videoplayer.player.AbstractPlayer;


public class ExoMediaPlayer extends AbstractPlayer implements Player.Listener {

    protected Context mAppContext;
    protected ExoPlayer mInternalPlayer;
    protected MediaSource mMediaSource;
    protected ExoMediaSourceHelper mMediaSourceHelper;
    protected ExoTrackNameProvider trackNameProvider;
    protected TrackSelectionArray mTrackSelections;
    private PlaybackParameters mSpeedPlaybackParameters;
    private boolean mIsPreparing;

    private LoadControl mLoadControl;
    private DefaultRenderersFactory mRenderersFactory;
    private DefaultTrackSelector mTrackSelector;


    public ExoMediaPlayer(Context context) {
        mAppContext = context.getApplicationContext();
        mMediaSourceHelper = ExoMediaSourceHelper.getInstance(context);
    }

    @Override
    public void initPlayer() {
        if (mRenderersFactory == null) {
            mRenderersFactory = new DefaultRenderersFactory(mAppContext);
        }
        mRenderersFactory.setExtensionRendererMode(DefaultRenderersFactory.EXTENSION_RENDERER_MODE_PREFER);
        if (mTrackSelector == null) {
            mTrackSelector = new DefaultTrackSelector(mAppContext);
        }
        if (mLoadControl == null) {
            mLoadControl =new DefaultLoadControl();
        }
        mTrackSelector.setParameters(mTrackSelector.getParameters().buildUpon().setTunnelingEnabled(true));
        /*mInternalPlayer = new SimpleExoPlayer.Builder(
                mAppContext,
                mRenderersFactory,
                mTrackSelector,
                new DefaultMediaSourceFactory(mAppContext),
                mLoadControl,
                DefaultBandwidthMeter.getSingletonInstance(mAppContext),
                new AnalyticsCollector(Clock.DEFAULT))
                .build();*/
        mInternalPlayer = new ExoPlayer.Builder(mAppContext)
                .setLoadControl(mLoadControl)
                .setRenderersFactory(mRenderersFactory)
                .setTrackSelector(mTrackSelector).build();

        setOptions();

        mInternalPlayer.addListener(this);
    }

    public DefaultTrackSelector getTrackSelector() {
        return mTrackSelector;
    }

    @Override
    public void setDataSource(String path, Map<String, String> headers) {
        mMediaSource = mMediaSourceHelper.getMediaSource(path, headers);
    }

    @Override
    public void setDataSource(AssetFileDescriptor fd) {
        //no support
    }

    @Override
    public void start() {
        if (mInternalPlayer == null)
            return;
        mInternalPlayer.setPlayWhenReady(true);
    }

    @Override
    public void pause() {
        if (mInternalPlayer == null)
            return;
        mInternalPlayer.setPlayWhenReady(false);
    }

    @Override
    public void stop() {
        if (mInternalPlayer == null)
            return;
        mInternalPlayer.stop();
    }

    @Override
    public void prepareAsync() {
        if (mInternalPlayer == null)
            return;
        if (mMediaSource == null) return;
        if (mSpeedPlaybackParameters != null) {
            mInternalPlayer.setPlaybackParameters(mSpeedPlaybackParameters);
        }
        mIsPreparing = true;
        mInternalPlayer.setMediaSource(mMediaSource);
        mInternalPlayer.prepare();
    }

    @Override
    public void reset() {
        if (mInternalPlayer != null) {
            mInternalPlayer.stop();
            mInternalPlayer.clearMediaItems();
            mInternalPlayer.setVideoSurface(null);
            mIsPreparing = false;
        }
    }

    @Override
    public boolean isPlaying() {
        if (mInternalPlayer == null)
            return false;
        int state = mInternalPlayer.getPlaybackState();
        switch (state) {
            case Player.STATE_BUFFERING:
            case Player.STATE_READY:
                return mInternalPlayer.getPlayWhenReady();
            case Player.STATE_IDLE:
            case Player.STATE_ENDED:
            default:
                return false;
        }
    }

    @Override
    public void seekTo(long time) {
        if (mInternalPlayer == null)
            return;
        mInternalPlayer.seekTo(time);
    }

    @Override
    public void release() {
        if (mInternalPlayer != null) {
            mInternalPlayer.removeListener(this);
            mInternalPlayer.release();
            mInternalPlayer = null;
        }
        lastTotalRxBytes = 0;
        lastTimeStamp = 0;
        mIsPreparing = false;
        mSpeedPlaybackParameters = null;
    }

    @Override
    public long getCurrentPosition() {
        if (mInternalPlayer == null)
            return 0;
        return mInternalPlayer.getCurrentPosition();
    }

    @Override
    public long getDuration() {
        if (mInternalPlayer == null)
            return 0;
        return mInternalPlayer.getDuration();
    }

    @Override
    public int getBufferedPercentage() {
        return mInternalPlayer == null ? 0 : mInternalPlayer.getBufferedPercentage();
    }

    @Override
    public void setSurface(Surface surface) {
        if (mInternalPlayer != null) {
            mInternalPlayer.setVideoSurface(surface);
        }
    }

    @Override
    public void setDisplay(SurfaceHolder holder) {
        if (holder == null)
            setSurface(null);
        else
            setSurface(holder.getSurface());
    }

    @Override
    public void setVolume(float leftVolume, float rightVolume) {
        if (mInternalPlayer != null)
            mInternalPlayer.setVolume((leftVolume + rightVolume) / 2);
    }

    @Override
    public void setLooping(boolean isLooping) {
        if (mInternalPlayer != null)
            mInternalPlayer.setRepeatMode(isLooping ? Player.REPEAT_MODE_ALL : Player.REPEAT_MODE_OFF);
    }

    @Override
    public void setOptions() {
        //准备好就开始播放
        mInternalPlayer.setPlayWhenReady(true);
    }

    @Override
    public void setSpeed(float speed) {
        PlaybackParameters playbackParameters = new PlaybackParameters(speed);
        mSpeedPlaybackParameters = playbackParameters;
        if (mInternalPlayer != null) {
            mInternalPlayer.setPlaybackParameters(playbackParameters);
        }
    }

    @Override
    public float getSpeed() {
        if (mSpeedPlaybackParameters != null) {
            return mSpeedPlaybackParameters.speed;
        }
        return 1f;
    }

    private long lastTotalRxBytes = 0;

    private long lastTimeStamp = 0;

    private boolean unsupported() {
        return TrafficStats.getUidRxBytes(App.getInstance().getApplicationInfo().uid) == TrafficStats.UNSUPPORTED;
    }

    @Override
    public long getTcpSpeed() {
        if (mAppContext == null || unsupported()) {
            return 0;
        }
        //使用getUidRxBytes方法获取该进程总接收量
        long total = TrafficStats.getTotalRxBytes();
        //记录当前的时间
        long time = System.currentTimeMillis();
        //数据接收量除以数据接收的时间，就计算网速了。
        long diff = total - lastTotalRxBytes;
        long speed = diff / Math.max(time - lastTimeStamp, 1);
        //当前时间存到上次时间这个变量，供下次计算用
        lastTimeStamp = time;
        //当前总接收量存到上次接收总量这个变量，供下次计算用
        lastTotalRxBytes = total;
        LOG.e("TcpSpeed",speed * 1024 + "");
        return speed * 1024;
    }

    @Override
    public void onTracksChanged(@NonNull TrackGroupArray trackGroups, @NonNull TrackSelectionArray trackSelections) {
        trackNameProvider = new ExoTrackNameProvider(mAppContext.getResources());
        mTrackSelections = trackSelections;
    }

    @Override
    public void onPlaybackStateChanged(int playbackState) {
        if (mPlayerEventListener == null) return;
        if (mIsPreparing) {
            if (playbackState == Player.STATE_READY) {
                mPlayerEventListener.onPrepared();
                mPlayerEventListener.onInfo(MEDIA_INFO_RENDERING_START, 0);
                mIsPreparing = false;
            }
            return;
        }
        switch (playbackState) {
            case Player.STATE_BUFFERING:
                mPlayerEventListener.onInfo(MEDIA_INFO_BUFFERING_START, getBufferedPercentage());
                break;
            case Player.STATE_READY:
                mPlayerEventListener.onInfo(MEDIA_INFO_BUFFERING_END, getBufferedPercentage());
                break;
            case Player.STATE_ENDED:
                mPlayerEventListener.onCompletion();
                break;
            case Player.STATE_IDLE:
                break;
        }
    }

    @Override
    public void onPlayerError(@NonNull PlaybackException error) {
        if (mPlayerEventListener != null) {
            mPlayerEventListener.onError();
        }
    }

    @Override
    public void onVideoSizeChanged(@NonNull VideoSize videoSize) {
        if (mPlayerEventListener != null) {
            mPlayerEventListener.onVideoSizeChanged(videoSize.width, videoSize.height);
            if (videoSize.unappliedRotationDegrees > 0) {
                mPlayerEventListener.onInfo(MEDIA_INFO_VIDEO_ROTATION_CHANGED, videoSize.unappliedRotationDegrees);
            }
        }
    }


}
