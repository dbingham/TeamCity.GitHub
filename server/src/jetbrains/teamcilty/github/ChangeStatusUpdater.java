/*
 * Copyright 2000-2012 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jetbrains.teamcilty.github;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.messages.Status;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.executors.ExecutorServices;
import jetbrains.buildServer.util.ExceptionUtil;
import jetbrains.buildServer.util.StringUtil;
import jetbrains.teamcilty.github.api.*;
import jetbrains.teamcilty.github.ui.UpdateChangeStatusFeature;
import jetbrains.teamcilty.github.ui.UpdateChangesConstants;
import jetbrains.teamcilty.github.util.LoggerHelper;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Created by Eugene Petrenko (eugene.petrenko@gmail.com)
 * Date: 06.09.12 3:29
 */
public class ChangeStatusUpdater {
  private static final Logger LOG = LoggerHelper.getInstance(ChangeStatusUpdater.class);
  private static final UpdateChangesConstants C = new UpdateChangesConstants();

  private final ExecutorService myExecutor;
  @NotNull
  private final GitHubApiFactory myFactory;
  private final WebLinks myWeb;

  public ChangeStatusUpdater(@NotNull final ExecutorServices services,
                             @NotNull final GitHubApiFactory factory,
                             @NotNull final WebLinks web) {
    myFactory = factory;
    myWeb = web;
    myExecutor = services.getLowPriorityExecutorService();
  }

  @NotNull
  private GitHubApi getGitHubApi(@NotNull final SBuildFeatureDescriptor feature) {
    final String serverUrl = feature.getParameters().get(C.getServerKey());
    if (serverUrl == null || StringUtil.isEmptyOrSpaces(serverUrl)) {
      throw new IllegalArgumentException("Failed to read GitHub URL from the feature settings");
    }

    final GitHubApiAuthenticationType authenticationType = GitHubApiAuthenticationType.parse(feature.getParameters().get(C.getAuthenticationTypeKey()));
    switch (authenticationType) {
      case PASSWORD_AUTH:
        final String username = feature.getParameters().get(C.getUserNameKey());
        final String password = feature.getParameters().get(C.getPasswordKey());
        return myFactory.openGitHubForUser(serverUrl, username, password);

      case TOKEN_AUTH:
        final String token = feature.getParameters().get(C.getAccessTokenKey());
        return myFactory.openGitHubForToken(serverUrl, token);

      default:
        throw new IllegalArgumentException("Failed to parse authentication type:" + authenticationType);
    }
  }

  @NotNull
  public Handler getUpdateHandler(@NotNull final SBuildFeatureDescriptor feature) {
    if (!feature.getType().equals(UpdateChangeStatusFeature.FEATURE_TYPE)) {
      throw new IllegalArgumentException("Unexpected feature type " + feature.getType());
    }

    final GitHubApi api = getGitHubApi(feature);

    final String repositoryOwner = feature.getParameters().get(C.getRepositoryOwnerKey());
    final String repositoryName = feature.getParameters().get(C.getRepositoryNameKey());
    @Nullable final String context = feature.getParameters().get(C.getContextKey());
    final boolean useGuestUrls = !StringUtil.isEmptyOrSpaces(feature.getParameters().get(C.getUseGuestUrlsKey()));

    final GitHubApiCommentEvent commentEvent = GitHubApiCommentEvent.parse(feature.getParameters().get(C.getUseCommentsKey()));
    final boolean shouldCommentAlways = commentEvent == GitHubApiCommentEvent.ALWAYS;
    final boolean shouldCommentWithStatus = commentEvent == GitHubApiCommentEvent.WITH_STATUS;

    final GitHubApiReportEvent reportEvent = GitHubApiReportEvent.parse(feature.getParameters().get(C.getReportOnKey()));
    final boolean shouldReportOnStart = reportEvent == GitHubApiReportEvent.ON_START_AND_FINISH || reportEvent == GitHubApiReportEvent.ON_START;
    final boolean shouldReportOnFinish = reportEvent == GitHubApiReportEvent.ON_START_AND_FINISH || reportEvent == GitHubApiReportEvent.ON_FINISH;
    final boolean shouldReportOnFailure = reportEvent == GitHubApiReportEvent.ON_FAILURE;
    final boolean shouldReportNever = reportEvent == GitHubApiReportEvent.NEVER;

    return new Handler() {
      @NotNull
      private String getViewResultsUrl(@NotNull final SRunningBuild build) {
        final String url = myWeb.getViewResultsUrl(build);
        if (useGuestUrls) {
          return url + (url.contains("?") ? "&" : "?") + "guest=1";
        }
        return url;
      }

      public boolean shouldUpdate( @NotNull final SRunningBuild build, final boolean starting ) {
        return shouldUpdateStatus( build, starting ) || shouldCommentAlways;
      }

      private boolean shouldUpdateStatus( @NotNull final SRunningBuild build, final boolean starting ) {
        if (shouldReportNever) return false;

        return starting && shouldReportOnStart ||
                !starting && shouldReportOnFinish ||
                !starting && shouldReportOnFailure && getGitHubChangeState(build) != GitHubChangeState.Success;
      }

      public void scheduleChangeStarted(@NotNull RepositoryVersion version, @NotNull SRunningBuild build) {
        String hash = resolveCommitHash(version, build, GitHubChangeState.Pending);
        if( shouldReportOnStart )
          scheduleChangeUpdate(version, build, "Started TeamCity Build " + build.getFullName(), GitHubChangeState.Pending, hash);
        if( shouldCommentAlways || (shouldCommentWithStatus && shouldReportOnStart) )
          scheduleComment(version, build, GitHubChangeState.Pending, hash);
      }

      public void scheduleChangeCompeted(@NotNull RepositoryVersion version, @NotNull SRunningBuild build) {
        LOG.debug("Status :" + build.getStatusDescriptor().getStatus().getText());
        LOG.debug("Status Priority:" + build.getStatusDescriptor().getStatus().getPriority());

        final GitHubChangeState status = getGitHubChangeState(build);
        final String text = getGitHubChangeText(build);
        final String hash = resolveCommitHash(version, build, status);
        final boolean willUpdateStatus = shouldReportOnFinish || (status != GitHubChangeState.Success && shouldReportOnFailure);

        if( willUpdateStatus )
          scheduleChangeUpdate(version, build, "Finished TeamCity Build " + build.getFullName() + " " + text, status, hash);
        if( shouldCommentAlways || (shouldCommentWithStatus && willUpdateStatus) )
          scheduleComment(version, build, status, hash);
      }

      @NotNull
      private String getGitHubChangeText(@NotNull final SRunningBuild build) {
        final String text = build.getStatusDescriptor().getText();
        if (text != null) {
          return ": " + text;
        } else {
          return "";
        }
      }

      @NotNull
      private GitHubChangeState getGitHubChangeState(@NotNull final SRunningBuild build) {
        final Status status = build.getStatusDescriptor().getStatus();
        final byte priority = status.getPriority();

        if (priority == Status.NORMAL.getPriority()) {
          return GitHubChangeState.Success;
        } else if (priority == Status.FAILURE.getPriority()) {
          return GitHubChangeState.Failure;
        } else {
          return GitHubChangeState.Error;
        }
      }

      @NotNull
      private String resolveCommitHash(@NotNull final RepositoryVersion version,
                                       @NotNull final SRunningBuild build,
                                       @NotNull final GitHubChangeState status) {
        final String vcsBranch = version.getVcsBranch();
        if (vcsBranch != null && api.isPullRequestMergeBranch(vcsBranch)) {
          try {
            final String hash = api.findPullRequestCommit(repositoryOwner, repositoryName, vcsBranch);
            if (hash == null) {
              throw new IOException("Failed to find head hash for commit from " + vcsBranch);
            }
            LOG.info("Resolved GitHub change commit for " + vcsBranch + " to point to pull request head for " +
                    "hash: " + version.getVersion() + ", " +
                    "newHash: " + hash + ", " +
                    "branch: " + version.getVcsBranch() + ", " +
                    "buildId: " + build.getBuildId() + ", " +
                    "status: " + status);
            return hash;
          } catch (IOException e) {
            LOG.warn("Failed to find status update hash for " + vcsBranch + " for repository " + repositoryName);
          }
        }
        return version.getVersion();
      }

      private void scheduleComment(@NotNull final RepositoryVersion version,
                                   @NotNull final SRunningBuild build,
                                   @NotNull final GitHubChangeState status,
                                   @NotNull final String commitHash) {
        LOG.info("Scheduling GitHub comment for " +
                "hash: " + version.getVersion() + ", " +
                "branch: " + version.getVcsBranch() + ", " +
                "buildId: " + build.getBuildId() + ", " +
                "status: " + status);

        myExecutor.submit(ExceptionUtil.catchAll("add comment on github", new Runnable() {
          @NotNull
          private String getFailureText(@Nullable final STestRun testRun) {
            final String no_data = "<no details avaliable>";
            if (testRun == null) return no_data;

            final String details = testRun.getFullText();
            if (details == null || StringUtil.isEmptyOrSpaces(details)) return no_data;

            return details;
          }

          @NotNull
          private String getFriendlyDuration(final long seconds) {
            long second = seconds % 60;
            long minute = (seconds / 60) % 60;
            long hour = seconds / 60 / 60;

            return String.format("%02d:%02d:%02d", hour, minute, second);
          }

          @NotNull
          private String getComment(@NotNull SRunningBuild build,
                                    boolean completed) {
            final StringBuilder comment = new StringBuilder();
            comment.append("TeamCity ");
            final SBuildType bt = build.getBuildType();
            if (bt != null) {
              comment.append(bt.getFullName());
            }
            comment.append(" [Build ");
            comment.append(build.getBuildNumber());
            comment.append("](");
            comment.append(getViewResultsUrl(build));
            comment.append(") ");

            if (completed) {
              comment.append("outcome was **").append(build.getStatusDescriptor().getStatus().getText()).append("**");
            } else {
              comment.append("is now running");
            }

            comment.append("\n");

            final String text = build.getStatusDescriptor().getText();
            if (completed && text != null) {
              comment.append("Summary: ");
              comment.append(text);
              comment.append(" Build time: ");
              comment.append(getFriendlyDuration(build.getDuration()));

              if (build.getBuildStatus() != Status.NORMAL) {

                final List<STestRun> failedTests = build.getFullStatistics().getFailedTests();
                if (!failedTests.isEmpty()) {
                  comment.append("\n### Failed tests\n");
                  comment.append("```\n");

                  for (int i = 0; i < failedTests.size(); i++) {
                    final STestRun testRun = failedTests.get(i);
                    comment.append("");
                    comment.append(testRun.getTest().getName().toString());
                    comment.append(": ");
                    comment.append(getFailureText(testRun));
                    comment.append("\n\n");

                    if (i == 10) {
                      comment.append("\n##### there are ")
                              .append(build.getFullStatistics().getFailedTestCount() - i)
                              .append(" more failed tests, see build details\n");
                      break;
                    }
                  }
                  comment.append("```\n");
                }
              }
            }

            return comment.toString();
          }

          public void run() {
            try {
              api.postComment(
                      repositoryOwner,
                      repositoryName,
                      commitHash,
                      getComment(build, status != GitHubChangeState.Pending)
              );
              LOG.info("Added comment to GitHub commit: " + commitHash + ", buildId: " + build.getBuildId() + ", status: " + status);
            } catch (IOException e) {
              LOG.warn("Failed add GitHub comment for branch: " + version.getVcsBranch() + ", buildId: " + build.getBuildId() + ", status: " + status + ". " + e.getMessage(), e);
            }
          }
        }));
      }

      private void scheduleChangeUpdate(@NotNull final RepositoryVersion version,
                                        @NotNull final SRunningBuild build,
                                        @NotNull final String message,
                                        @NotNull final GitHubChangeState status,
                                        @NotNull final String commitHash) {
        LOG.info("Scheduling GitHub status update for " +
                "hash: " + version.getVersion() + ", " +
                "branch: " + version.getVcsBranch() + ", " +
                "buildId: " + build.getBuildId() + ", " +
                "status: " + status);

        myExecutor.submit(ExceptionUtil.catchAll("set change status on github", new Runnable() {
          public void run() {
            try {
              api.setChangeStatus(
                      repositoryOwner,
                      repositoryName,
                      commitHash,
                      status,
                      getViewResultsUrl(build),
                      message,
                      context
              );
              LOG.info("Updated GitHub status for hash: " + commitHash + ", buildId: " + build.getBuildId() + ", status: " + status);
            } catch (IOException e) {
              LOG.warn("Failed to update GitHub status for hash: " + commitHash + ", buildId: " + build.getBuildId() + ", status: " + status + ". " + e.getMessage(), e);
            }
          }
        }));
      }
    };
  }

  public interface Handler {
    boolean shouldUpdate( @NotNull  final SRunningBuild build, final boolean starting);
    void scheduleChangeStarted(@NotNull final RepositoryVersion hash, @NotNull final SRunningBuild build);
    void scheduleChangeCompeted(@NotNull final RepositoryVersion hash, @NotNull final SRunningBuild build);
  }
}
